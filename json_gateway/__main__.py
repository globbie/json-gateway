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
import sys

import translator
from translator import KnowdyService

logger = logging.getLogger(__name__)
MAX_RETRIEVE_ATTEMPTS = 10
RETRIEVE_TIMEOUT = 0.05  # ms


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
        task = "{task {user{auth{sid AUTH_SERVER_SID}}{retrieve {tid %s}}}}" % (self.tid)
        messages.append(task.encode('utf-8'))
        messages.append("None".encode('utf-8'))
        socket.send_multipart(messages)

        head = socket.recv()
        msg = socket.recv()

        logger.debug(msg)

        body = json.loads(msg.decode('utf-8'))
        if "status" in body:
            self.send_wait_reply()
            return

        # TODO: set http return codes based on result

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

        task = "{task  {user {auth{sid AUTH_SERVER_SID}} {retrieve {tid %s}}}}" % (self.tid)
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
            print("RETRIEVAL attempt: %d.." % num_attempts)
            print(msg)
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

    def check_auth_token(self, tok):
        print(".. checking token: %s" % tok)
        ctx = zmq.Context()
        socket = ctx.socket(zmq.REQ)
        socket.connect(KnowdyService.auth.value['address'])

        messages = []
        task = "{task{user{auth{sid %s}}}}" % (tok)
        messages.append(task.encode('utf-8'))
        messages.append("None".encode('utf-8'))
        socket.send_multipart(messages)

        # reply from auth
        head = socket.recv()
        msg = socket.recv()
        logger.debug(msg)

        # HACK to fix initial corrupted '{'
        msg_array = bytearray(msg)
        msg_array[0] = ord('{')
        msg = b''.join(msg_array) 

        body = json.loads(msg.decode('utf-8'))
        socket.close()

        http_code = 401
        if "http_code" in body:
            http_code = body["http_code"]

        if http_code == 401:
            self.do_AUTHHEAD()
            return

        if http_code == 200:
            self.run_POST(body)
            return

        # some other error
        self.send_response(http_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(msg)

    def run_GET(self):
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

    def run_POST(self, auth_rec):
        length = int(self.headers['Content-Length'])
        post_body = self.rfile.read(length).decode('utf-8')

        self.tid = str(uuid.uuid4())

        return_body = dict()
        messages = []
        try:
            translation = translator.Translation(post_body, self.tid, auth_rec["user_id"])
            print(translation.gsl_result)
            logger.debug(translation.gsl_result)
            logger.debug(repr(translation.service))

            ctx = zmq.Context()
            if translation.service == KnowdyService.delivery:
                socket = ctx.socket(zmq.REQ)
            else:
                socket = ctx.socket(zmq.PUSH)
            socket.connect(translation.service.value['address'])
            messages.append(translation.gsl_result.encode('utf-8'))
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
        reply = json.dumps(return_body).encode('utf-8')
        self.wfile.write(reply)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Bearer realm=\"test\"')
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        if not 'Authorization' in self.headers:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received'.encode("utf-8"))
            return

        auth_string = self.headers['Authorization']
        if auth_string.startswith("Bearer"):
            self.check_auth_token(auth_string[7:].strip())
            return

        self.do_AUTHHEAD()

    def do_POST(self):
        if not 'Authorization' in self.headers:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received'.encode("utf-8"))
            return

        auth_string = self.headers['Authorization']
        if auth_string.startswith("Bearer"):
            self.check_auth_token(auth_string[7:].strip())
            return
        self.do_AUTHHEAD()

def main():
    parser = argparse.ArgumentParser(description='Handles json request to Knowdy via HTTP')
    parser.add_argument('-i', '--interface', default='0.0.0.0', type=str, help='The interface to listen')
    parser.add_argument('-p', '--port', default='8000', type=int, help='Service port')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show debug logs')
    parser.add_argument('-l', '--log-path', default='json-gsl-gateway.log', help='log file')
    parser.add_argument('-s', '--service', action='store_true', help='Print logs to stdout in service mode')

    args = parser.parse_args()
    logger.setLevel(logging.INFO)
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(filename)s:%(lineno)d [%(levelname)-6s] (%(asctime)s): %(message)s')

    if not args.service:
        handler = logging.handlers.RotatingFileHandler(args.log_path, maxBytes=(50 * 1024 ** 2), backupCount=5)
        handler.setLevel(logger.level)
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logger.level)
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    Handler = JsonGateway
    Handler.server_version = "Knowdy HTTP Gateway"

    httpd = socketserver.TCPServer((args.interface, args.port), Handler)
    logger.info("serving at %s:%s" % (args.interface, args.port))
    httpd.serve_forever()

if __name__ == '__main__':
    main()
