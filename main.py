import http.server
import socketserver
import zmq
import json

HOST = '0.0.0.0'
PORT = 8000

GLB_DELIVERY_ADDR = "ipc:///var/lib/knowdy/delivery/inbox"
GLB_COLLECTION_ADDR = "tcp://127.0.0.1:6908"


def json_to_gsl(input_json: str) -> str:
    input_ = json.loads(input_json)
    output_ = json.dumps(input_)

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

        ctx = zmq.Context()
        socket = ctx.socket(zmq.PUSH)
        socket.connect(GLB_COLLECTION_ADDR)

        messages = []

        task = """{knd::Task
                      {tid 123456}
                      {user
                          (auth {sid AUTH_SERVER_SID})
                          {repo
                              (add {n R4S Content})}
                      }
                  }"""

        messages.append(task.encode('utf-8'))
        messages.append("None".encode('utf-8'))

        socket.send_multipart(messages)

        self.wfile.write(json_to_gsl(post_body).encode('utf-8'))

        return

Handler = JsonGateway

httpd = socketserver.TCPServer((HOST, PORT), Handler)
print("serving at %s:%s" % (HOST, PORT))
httpd.serve_forever()
