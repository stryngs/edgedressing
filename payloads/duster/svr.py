import http.server
import socketserver
import json

# Directory to serve files from
DIRECTORY = "./"

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        """Ensure the handler serves files from the DIRECTORY variable."""
        return super().translate_path(path)

    def do_POST(self):
        if self.path == '/report':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            print("Data received from browser:")
            for key, value in data.items():
                print(f"{key}: {value}")
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

# Start the server
PORT = 8000
with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
    print(f"Serving at http://0.0.0.0:{PORT}")
    httpd.serve_forever()