#!/usr/bin/env python3

import http.server
import socketserver
import zmq
import json
import uuid
import logging.handlers
import argparse
from time import sleep
from os import curdir, sep

from urllib.parse import urlparse

import translator
from translator import KnowdyService

logger = logging.getLogger(__name__)
MAX_RETRIEVE_ATTEMPTS = 10
RETRIEVE_TIMEOUT = 0.05  # ms


def json_to_gsl(input_json: str, tid: str) -> (str, dict, bool):
    is_async = False
    input_ = json.loads(input_json)

    output_ = ['{knd::Task {tid %s} ' % str(tid)]
    request = input_['request']
    schema = request['schema']

    if 'async' in input_:
        if input_['async']:
            is_async = True

    user = request['user']
    output_.append('{user ')

    auth = user['auth']
    output_.append('(auth ')

    sid = auth['sid']
    output_.append('{sid %s}) ' % sid)

    if 'retrieve' in user:  # delivery server request hackery
        tid = user['retrieve']['tid']

        output_ = "{knd::Task {tid %s} {sid %s} {retrieve _obj}}" % (tid, sid)
        return output_, KnowdyService.delivery, is_async

    service = KnowdyService.write

    if 'class' in user:
        c = user['class']
        output_.append('{class %s}' % c)
        service = KnowdyService.read
        
    if 'repo' in user:
        repo = user['repo']
        output_.append('{repo ')

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
    return output_, service, is_async


class JsonGateway(http.server.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super(JsonGateway, self).__init__(request, client_address, server)
        self.tid = None
        self.sid = None

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
        # reply = json.dumps(body).encode('utf-8')
        self.wfile.write(msg)

    def send_wait_reply(self):
        return_body = dict()
        return_body['status'] = "in progress"
        return_body['estimate'] = "5m"
        self.send_response(202)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        reply = json.dumps(return_body).encode('utf-8')
        self.wfile.write(reply)

    def send_bad_request(self):
        return_body = dict()
        return_body['error'] = "malformed request"
        logger.warning("malformed request")
        self.send_response(400)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        return_body = json.dumps(return_body).encode('utf-8')
        self.wfile.write(return_body)

    def async_reply(self):
        return_body = dict()
        return_body['tid'] = str(self.tid)
        self.send_response(202)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        return_body = json.dumps(return_body).encode('utf-8')
        self.wfile.write(return_body)

    def retrieve_result(self, socket):
        head = socket.recv()
        msg = socket.recv().decode('utf-8')
        logger.debug(msg)
        return_body = json.loads(msg)
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        return_body = json.dumps(return_body).encode('utf-8')
        self.wfile.write(return_body)

    def wait_for_result(self):
        messages = []
        task = "{knd::Task {tid %s} {sid AUTH_SERVER_SID} {retrieve _obj}}" % self.tid
        messages.append(task.encode('utf-8'))
        messages.append("None".encode('utf-8'))
        msg = "{\"error\": \"timed out\"}".encode('utf-8')
        timeout = RETRIEVE_TIMEOUT
        num_attempts = 0

        while 1:
            sleep(timeout)
            ctx = zmq.Context()
            socket = ctx.socket(zmq.REQ)
            socket.connect(KnowdyService.delivery.value['address'])
            socket.send_multipart(messages)

            head = socket.recv()
            msg = socket.recv()
            logger.debug(msg)
            socket.close()

            body = json.loads(msg.decode('utf-8'))
            if 'wait' not in body:
                break

            num_attempts += 1
            if num_attempts > MAX_RETRIEVE_ATTEMPTS:
                break
            timeout *= 2

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(msg)

    def do_GET(self):
        filename = self.path
        if self.path.endswith("/"):
            filename += "index.html"
        
        try:
            f = open(curdir + sep + filename, mode='rb')
            self.send_response(200)
            data = f.read()
            text = None
            if filename.endswith(".html"):
                self.send_header('Content-type', 'text/html')
            elif  filename.endswith(".js"):
                self.send_header('Content-type', 'text/javascript')
            elif  filename.endswith(".css"):
                self.send_header('Content-type', 'text/css')
            elif  filename.endswith(".svg"):
                self.send_header('Content-type', 'image/svg+xml')
            elif filename.endswith(".jpg"):
                self.send_header('Content-type', 'image/jpeg')
            elif filename.endswith(".woff"):
                self.send_header('Content-type', 'application/font-woff')
            elif filename.endswith(".png"):
                self.send_header('Content-type', 'image/png')
            else:
                self.send_header('Content-type', 'application/binary')

            self.end_headers()

            #if text:
            #    self.wfile.write(text)
            #else:
            self.wfile.write(data)
                
            f.close()
            return
        except IOError:
            self.send_error(404, 'File Not Found: %s' % self.path)
            return
        
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

        self.tid = str(uuid.uuid4())

        return_body = dict()

        messages = []
        try:
            translation = translator.Translation(post_body, self.tid)

            logger.debug(translation.gsl_result)
            logger.debug(repr(translation.service))

            ctx = zmq.Context()
            if translation.service == KnowdyService.delivery:
                socket = ctx.socket(zmq.REQ)
            else:
                socket = ctx.socket(zmq.PUSH)

            socket.connect(translation.service.value['address'])

            messages.append(translation.gsl_result)
            messages.append("None".encode('utf-8'))
            socket.send_multipart(messages)

            if translation.async:
                self.async_reply()
                socket.close()
                return

            if translation.service == KnowdyService.delivery:
                self.retrieve_result(socket)
                socket.close()
                return

            socket.close()
            self.wait_for_result()
            return

        except KeyError as e:
            return_body['error'] = "malformed request"
            logger.warning("malformed request")
            self.send_response(400)
        except Exception as e:
            logger.exception(e)
            return_body['error'] = "internal error"
            logger.exception("internal error")
            self.send_response(500)

        self.send_header('Content-type', 'application/json')
        self.end_headers()
        return_body = json.dumps(return_body).encode('utf-8')
        self.wfile.write(return_body)


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
    Handler.server_version = "Knowdy HTTP Gateway"

    httpd = socketserver.TCPServer((args.interface, args.port), Handler)
    logger.info("serving at %s:%s" % (args.interface, args.port))

    httpd.serve_forever()
