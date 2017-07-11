#!/usr/bin/env python3

import http.server
import socketserver
import zmq
import json
import uuid
import logging.handlers
import argparse
import enum

from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class KnowdyService(enum.Enum):
    delivery = {'address': 'ipc:///var/lib/knowdy/delivery/inbox'}
    read = {'address': 'tcp://127.0.0.1:6900'}
    write = {'address': 'tcp://127.0.0.1:6908'}


def json_to_gsl(input_json: str, ticket_id: str) -> (str, bool):
    input_ = json.loads(input_json)

    output_ = ['{knd::Task {tid %s} ' % str(ticket_id)]

    request = input_['request']
    schema = request['schema']

    user = request['user']
    output_.append('{user ')

    auth = user['auth']
    output_.append('(auth ')

    sid = auth['sid']
    output_.append('{sid %s}) ' % sid)

    if 'retrieve' in user:  # delivery server request hackery
        tid = user['retrieve']['tid']

        output_ = "{knd::Task {tid %s} {sid %s} {retrieve _obj}}" % (tid, sid)
        return output_, KnowdyService.delivery

    repo = user['repo']
    output_.append('{repo ')

    service = KnowdyService.write

    if 'add' in repo:  # new repo add case
        add = repo['add']
        output_.append('(add ')

        name = add['n']
        output_.append('{n %s})' % name)

    elif 'n' in repo:  # some actions with existent repo
        name = repo['n']
        output_.append('{n %s}' % name)

        class_ = repo['class']
        class_name = class_['n']

        output_.append('{class {n %s} ' % class_name)

        if 'obj' in class_:  # read object
            output_.append('{obj {n %s}}' % class_['obj']['n'])

        output_.append('}')
        service = KnowdyService.read

    else:
        raise KeyError

    output_ = "".join(output_)
    return output_, service


class JsonGateway(http.server.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super(JsonGateway, self).__init__(request, client_address, server)
        pass

    def ask_delivery(self):
        ctx = zmq.Context()
        socket = ctx.socket(zmq.REQ)
        
        socket.connect(KnowdyService.delivery.value['address'])

        messages = []
        task = "{knd::Task {tid %s} {sid AUTH_SERVER_SID} {retrieve _obj}}" % (self.tid)

        messages.append(task.encode('utf-8'))
        messages.append("None".encode('utf-8'))
        socket.send_multipart(messages)

        head = socket.recv()
        msg = socket.recv()

        logger.debug(msg)

        body = json.loads(msg.decode('utf-8'))
        if "result" not in body:
            self.send_wait_reply()
            return
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        #reply = json.dumps(body).encode('utf-8')
        self.wfile.write(msg)

    def send_wait_reply(self):
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        return_body = dict()
        return_body['status'] = "in progress"
        return_body['estimate'] = "5m"
        self.send_response(202)
        reply = json.dumps(return_body).encode('utf-8')
        self.wfile.write(reply)

    def send_bad_request(self):
        return_body = dict()
        return_body['error'] = "malformed request"
        logger.warning("malformed request")
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.send_response(400)
        return_body = json.dumps(return_body).encode('utf-8')
        self.wfile.write(return_body)
        
    def do_GET(self):
        params = dict()
        
        query = urlparse(self.path).query
        if "&" not in query:
            self.send_bad_request()
            return

        for qc in query.split("&"):
            if "=" not in qc:
                self.send_bad_request()
                return
            (k, v) = qc.split("=")
            params[k] = v
            
        if "sid" not in params:
            self.send_bad_request()
            return

        if "tid" not in params:
            self.send_bad_request()
            return

        self.tid = params["tid"]
        self.sid = params["sid"]
        self.ask_delivery()
        

    def do_POST(self):

        length = int(self.headers['Content-Length'])
        post_body = self.rfile.read(length).decode('utf-8')

        ticket_id = uuid.uuid4()

        return_body = dict()

        messages = []
        try:
            result = json_to_gsl(post_body, ticket_id)
            task = result[0].encode('utf-8')
            service = result[1]

            logger.debug(task)
            logger.debug(repr(service))

            ctx = zmq.Context()
            if service == KnowdyService.delivery:
                socket = ctx.socket(zmq.REQ)
            else:
                socket = ctx.socket(zmq.PUSH)

            socket.connect(service.value['address'])

            messages.append(task)
            messages.append("None".encode('utf-8'))
            socket.send_multipart(messages)

            return_body['tid'] = str(ticket_id)

            self.send_response(202)

            if service == KnowdyService.delivery:
                head = socket.recv()
                msg = socket.recv().decode('utf-8')
                logger.debug(msg)
                return_body = json.loads(msg)
        except KeyError as e:
            return_body['error'] = "malformed request"
            logger.warning("malformed request")
            self.send_response(400)
        except Exception as e:
            return_body['error'] = "internal error"
            logger.exception("internal error")
            self.send_response(500)

        self.send_header('Content-type', 'application/json')
        self.end_headers()

        return_body = json.dumps(return_body).encode('utf-8')
        self.wfile.write(return_body)

        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Handles json request to Knowdy via HTTP')
    parser.add_argument('-i', '--interface', default='0.0.0.0', type=str, help='The interface to listen')
    parser.add_argument('-p', '--port', default='8000', type=int, help='Service port')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show debug logs')
    parser.add_argument('-l', '--log-path', default='json-gsl-gateway.log', help='log file')

    args = parser.parse_args()

    logger.setLevel(logging.INFO)
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    handler = logging.handlers.RotatingFileHandler(args.log_path, maxBytes=(50 * 1024 ** 2), backupCount=5)
    handler.setLevel(logger.level)

    formatter = logging.Formatter('%(filename)s:%(lineno)d [%(levelname)-6s] (%(asctime)s): %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    Handler = JsonGateway

    httpd = socketserver.TCPServer((args.interface, args.port), Handler)
    logger.info("serving at %s:%s" % (args.interface, args.port))

    httpd.serve_forever()
