import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

STATIC_CONTENT = ""


class StoppableHTTPServer(HTTPServer):
    def serve_forever(self):
        self.handle_request()


def getStaticContent():
    return STATIC_CONTENT.encode("utf-8")


class CustomHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        print("Incoming Request from " + self.client_address[0])
        self._set_response()
        self.wfile.write(getStaticContent())
        self.wfile.flush()

    def do_SILENT_TERMINATE(self):
        pass

    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/x+php')
        self.end_headers()


def run_http_server(port, static_content):
    global STATIC_CONTENT
    STATIC_CONTENT = static_content
    server = StoppableHTTPServer(('localhost', port), CustomHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    thread.join()
