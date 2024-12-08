#!/usr/bin/python3

import requests
import os

def read_successful_ports(file_path):
    """
    Reads the successful_ports.txt file and returns a list of URLs.
    """
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def read_cookies_file(file_path):
    """
    Reads cookies.ckl file and returns a dictionary of cookies.
    """
    cookies = {}
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            for line in file:
                if "=" in line:
                    # Extract cookie name and value
                    cookie = line.split(";")[0]  # Ignore attributes like Path or HttpOnly
                    name, value = cookie.split("=", 1)
                    cookies[name.strip()] = value.strip()
    return cookies

def extract_cookies(response):
    """
    Extracts cookies from the response object.
    """
    return response.cookies.get_dict()

def perform_requests(urls, initial_cookies):
    """
    Sends GET requests to each URL and collects cookies.
    """
    learned_cookies = initial_cookies.copy()  # Start with cookies from cookies.ckl

    # First round of GET requests
    print("\n--- First GET Requests ---")
    for url in urls:
        try:
            response = requests.get(url, cookies=initial_cookies)
            print(f"GET {url}: Status {response.status_code}")
            cookies = extract_cookies(response)
            print(f"Cookies Received: {cookies}")
            learned_cookies.update(cookies)
        except Exception as e:
            print(f"Error with {url}: {e}")

    # # Second round of GET requests with learned cookies
    # print("\n--- Second GET Requests ---")
    # for url in urls:
    #     try:
    #         response = requests.get(url, cookies=learned_cookies)
    #         print(f"GET {url} with Cookies: Status {response.status_code}")
    #         cookies = extract_cookies(response)
    #         print(f"Additional Cookies Received: {cookies}")
    #         learned_cookies.update(cookies)  # Update cookies if more are received
    #     except Exception as e:
    #         print(f"Error with {url}: {e}")

    return learned_cookies

def main():
    # File paths
    successful_ports_path = "successful_ports.txt"
    cookies_file_path = "cookies.ckl"

    # Read URLs from successful_ports.txt
    urls = read_successful_ports(successful_ports_path)
    if not urls:
        print("No URLs found in successful_ports.txt.")
        return

    # Read cookies from cookies.ckl if it exists
    initial_cookies = read_cookies_file(cookies_file_path)
    if initial_cookies:
        print("\n--- Cookies Loaded from cookies.ckl ---")
        print(initial_cookies)
    else:
        print("\n--- No cookies.ckl file found or file is empty ---")

    # Perform requests and collect cookies
    final_cookies = perform_requests(urls, initial_cookies)

    print("\n--- Final Cookie Set ---")
    print(final_cookies)

if __name__ == "__main__":
    main()
