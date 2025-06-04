import argparse
import requests
import concurrent.futures
import socket
from urllib.parse import urlparse

DEFAULT_WORDLIST = "directory-list-2.3-medium.txt"

def is_port_open(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def scan_directory(url, directory):
    target_url = f"{url}/{directory}"
    try:
        methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE']
        for method in methods:
            response = requests.request(method, target_url)
            if response.status_code == 200:
                return (target_url, True)
            elif response.status_code == 403:
                return (target_url, False)
            elif response.status_code == 404:
                continue
            elif response.status_code == 301 or response.status_code == 302:
                return (target_url, False)
            else:
                return (target_url, False)
        return (target_url, False)
    except requests.RequestException as e:
        return (target_url, False)

def directory_buster(url, wordlist, port=None, max_workers=10):
    with open(wordlist, 'r') as f:
        directories = f.readlines()

    total_directories = len(directories)
    found_directories = 0

    print(f"Scanning {total_directories} directories...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for directory in directories:
            directory = directory.strip()  # Remove newline characters
            futures.append(executor.submit(scan_directory, url, directory))

        for future in concurrent.futures.as_completed(futures):
            target_url, found = future.result()
            if found:
                print(f"[+] Directory found: {target_url}")
                found_directories += 1

    print("Scan complete.")





def main():
    parser = argparse.ArgumentParser(description='Directory Buster')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-w', '--wordlist', default=DEFAULT_WORDLIST, help='Path to wordlist file (default: %(default)s)')
    parser.add_argument('-p', '--port', type=int, help='Port to connect to (default: 80 if not specified)')
    args = parser.parse_args()

    parsed_url = urlparse(args.url)
    host = parsed_url.hostname
    port = args.port or parsed_url.port or 80

    if is_port_open(host, port):
        directory_buster(args.url, args.wordlist, port)
    else:
        print(f"[-] Port {port} is not open on the specified host.")

if __name__ == "__main__":
    main()
