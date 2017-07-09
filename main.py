import http.server
import socketserver
import zmq
import json
import uuid
import logging

HOST = '0.0.0.0'
PORT = 8001

GLB_DELIVERY_ADDR = "ipc:///var/lib/knowdy/delivery/inbox"
GLB_COLLECTION_ADDR = "tcp://127.0.0.1:6908"


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
        return output_, True

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

        if 'obj' in class_:
            output_.append('{obj {n %s}}' % class_['obj']['n'])

        output_.append('}')

    else:
        raise KeyError

    output_ = "".join(output_)
    return output_, False


class JsonGateway(http.server.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super(JsonGateway, self).__init__(request, client_address, server)
        pass

    def do_GET(self):
        self.send_response(200)

        self.send_header('Content-type', 'application/json')
        self.end_headers()
        return

    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        length = int(self.headers['Content-Length'])
        post_body = self.rfile.read(length).decode('utf-8')

        ticket_id = uuid.uuid4()

        return_body = dict()

        messages = []

        try:
            result = json_to_gsl(post_body, ticket_id)
            task = result[0].encode('utf-8')
            logging.debug(task)

            if result[1]:
                ctx = zmq.Context()
                socket = ctx.socket(zmq.REQ)
                socket.connect(GLB_DELIVERY_ADDR)
            else:
                ctx = zmq.Context()
                socket = ctx.socket(zmq.PUSH)
                socket.connect(GLB_COLLECTION_ADDR)

            messages.append(task)
            messages.append("None".encode('utf-8'))
            socket.send_multipart(messages)

            return_body['tid'] = str(ticket_id)

            if result[1]:
                head = socket.recv()
                msg = socket.recv()
                return_body = json.loads(msg)

        except KeyError as e:
            return_body['error'] = "malformed request"
            logging.warning("malformed request")
        except Exception as e:
            return_body['error'] = "internal error"
            logging.exception("internal error")

        return_body = json.dumps(return_body).encode('utf-8')
        self.wfile.write(return_body)

        return

Handler = JsonGateway

logging.basicConfig(level=logging.DEBUG)

httpd = socketserver.TCPServer((HOST, PORT), Handler)
logging.info("serving at %s:%s" %(HOST, PORT))

httpd.serve_forever()
