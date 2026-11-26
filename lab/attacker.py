"""The lab's attacker: logs every request it receives, which is exactly what must not happen."""

from http.server import BaseHTTPRequestHandler, HTTPServer


class Log(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"ATTACKER RECEIVED: {self.path}", flush=True)
        self.send_response(204)
        self.end_headers()

    do_POST = do_GET

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 80), Log).serve_forever()
