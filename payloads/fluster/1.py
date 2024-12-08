#!/usr/bin/python3

import os
import random
import string
import socket
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import argparse
import time

# Global lists to track successful and failed ports
successful_ports = []
failed_ports = []

# Function to find and reserve available ports
def find_and_reserve_ports(start_port, num_ports):
    reserved_ports = []
    sockets = []
    for port in range(start_port, start_port + num_ports):
        try:
            # Create a socket and bind to the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", port))
            sockets.append(sock)  # Keep the socket open to reserve the port
            reserved_ports.append(port)
        except OSError as e:
            failed_ports.append((port, str(e)))  # Log failed ports with error
            continue  # Port is in use, skip
        if len(reserved_ports) == num_ports:
            break
    return reserved_ports, sockets

# Function to generate random strings
def generate_random_string(length, alphanumeric=True):
    characters = string.ascii_letters + (string.digits if alphanumeric else "")
    return ''.join(random.choices(characters, k=length))

# Function to generate random cookies
def generate_random_cookies(num_cookies, value_length):
    cookies = []
    for _ in range(num_cookies):
        name = generate_random_string(8, alphanumeric=False)  # Random alpha name
        value = generate_random_string(value_length)  # Random alphanumeric value
        cookies.append(f"{name}={value}; Path=/; HttpOnly")
    return cookies

# Write cookies to a file if requested
def write_cookies_to_file(file_name, cookies):
    with open(file_name, "w") as f:
        for cookie in cookies:
            f.write(cookie + "\n")
    print(f"Successfully wrote {len(cookies)} cookies to {file_name}")

# Generate the HTML file with iframes
def generate_html(ports, cookies, output_file):
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cookie Choke Test</title>
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
    # Add iframes for each port
    for port in ports:
        html += f'    <iframe src="http://127.0.0.1:{port}"></iframe>\n'

    # Add cookies via JavaScript
    html += """
    <script>
        document.cookie = `""" + "`;\n        document.cookie = `".join(cookies) + """`;
    </script>
</body>
</html>
"""
    with open(output_file, "w") as file:
        file.write(html)
    print(f"Generated HTML file with {len(ports)} ports and {len(cookies)} cookies at {output_file}.")
    print("Ports used for iframes:\n" + "\n".join([f"http://127.0.0.1:{port}" for port in ports]))

# Custom HTTP Handler for lightweight servers
class LightweightHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        global cookies

        # Send HTTP status
        self.send_response(200)

        # Generate and set cookies
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)

        # Respond with a simple message
        self.end_headers()
        self.wfile.write(b"Lightweight server running!")

    def do_POST(self):
        """
        Handle POST requests, logging or saving the data received in the POST body.
        """
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        # Log the POST data
        print(f"POST received from {self.client_address}:")
        print(post_data)

        # Optionally save POST data to a file
        with open("post_data.log", "a") as log_file:
            log_file.write(f"POST received from {self.client_address}:\n")
            log_file.write(post_data + "\n\n")

        # Respond to the POST request
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"POST request received and logged!")

# Function to start a lightweight server on a specific port
def start_lightweight_server(port):
    global successful_ports, failed_ports
    try:
        server = HTTPServer(("127.0.0.1", port), LightweightHandler)
        successful_ports.append(port)  # Only add after successful binding
        print(f"Lightweight server successfully started on port {port}")
        server.serve_forever()
    except OSError as e:
        failed_ports.append((port, str(e)))  # Log failed ports with error
        print(f"Failed to start server on port {port}: {e}")

# Write successful ports to a file
def write_successful_ports(file_name, ports):
    with open(file_name, "w") as f:
        for port in ports:
            f.write(f"http://127.0.0.1:{port}\n")
    print(f"Successfully wrote {len(ports)} ports to {file_name}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Generate and serve an HTML file with iframes and cookies.")
    parser.add_argument("--port", type=int, default=8080, help="Starting port for the webserver (default: 8080)")
    parser.add_argument("-r", type=int, default=10, help="Number of ports to include in the iframes.")
    parser.add_argument("-c", type=int, default=20, help="Number of cookies to generate.")
    parser.add_argument("-v", type=int, default=10, help="Length of cookie values.")
    parser.add_argument("-o", type=str, default="index.html", help="Output HTML file name.")
    parser.add_argument("--output-ports", type=str, default="successful_ports.txt", help="Output file for successful ports.")
    parser.add_argument("--cookie", action="store_true", help="Write cookies to a file named 'cookies.ckl'.")
    parser.add_argument("--bind-global", action="store_true", help="Serve globally on 0.0.0.0 (default: 127.0.0.1)")
    args = parser.parse_args()

    # Reserve ports
    ports, sockets = find_and_reserve_ports(args.port, args.r)
    if not ports:
        print("No available ports found in the specified range.")
        return

    # Release reserved sockets before launching servers
    for sock in sockets:
        sock.close()

    # Generate cookies
    global cookies
    cookies = generate_random_cookies(args.c, args.v)

    # Write cookies to a file if --cookie is set
    if args.cookie:
        write_cookies_to_file("cookies.ckl", cookies)

    # Generate the HTML file
    generate_html(ports, cookies, args.o)

    # Determine bind address
    bind_address = "0.0.0.0" if args.bind_global else "127.0.0.1"
    print(f"Starting lightweight servers on http://{bind_address}:{args.port}")

    # Start lightweight servers for all ports in a separate thread
    threads = []
    for port in ports:
        thread = threading.Thread(target=start_lightweight_server, args=(port,), daemon=True)
        threads.append(thread)
        thread.start()

    # Wait for threads to finish initialization
    print("Waiting for lightweight servers to confirm startup...")
    for thread in threads:
        thread.join(timeout=0.1)  # Allow threads some time to attempt startup

    # Write successful ports to the specified file
    write_successful_ports(args.output_ports, successful_ports)

    # Print final status
    print("All lightweight servers are running. Press Ctrl+C to terminate.")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
