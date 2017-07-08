import http.server
import socketserver
import zmq
import json
import uuid

HOST = '0.0.0.0'
PORT = 8001

GLB_DELIVERY_ADDR = "ipc:///var/lib/knowdy/delivery/inbox"
GLB_COLLECTION_ADDR = "tcp://127.0.0.1:6908"


def json_to_gsl(input_json: str, ticket_id: str) -> str:
    input_ = json.loads(input_json)

    output_ = '{knd::Task {tid %s} ' % str(ticket_id)

    request = input_['request']
    schema = request['schema']

    user = request['user']
    output_ += '{user '

    auth = user['auth']
    output_ += '(auth '

    sid = auth['sid']
    output_ += '{sid %s}) ' % sid

    repo = user['repo']
    output_ += '{repo '

    add = repo['add']
    output_ += '(add '

    name = add['n']
    output_ += '{n %s})' % name

    print(output_)
    return output_


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

        ctx = zmq.Context()
        socket = ctx.socket(zmq.PUSH)
        socket.connect(GLB_COLLECTION_ADDR)

        messages = []

        try:
            task = json_to_gsl(post_body, ticket_id).encode('utf-8')

            messages.append(task)
            messages.append("None".encode('utf-8'))

            socket.send_multipart(messages)

            return_body['tid'] = str(ticket_id)

        except KeyError as e:
            return_body['error'] = "unknown key"
        except Exception as e:
            return_body['error'] = "internal error"

        self.wfile.write(json.dumps(return_body).encode('utf-8'))

        return

Handler = JsonGateway

httpd = socketserver.TCPServer((HOST, PORT), Handler)
print("serving at %s:%s" % (HOST, PORT))
httpd.serve_forever()
