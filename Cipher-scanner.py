import os
import platform
import sys
import subprocess
import re
import socket
import requests

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
WHITE = "\033[37m"
RESET = "\033[0m"

# Function to ping a host
def ping_host(host):
    command = ['ping', '-n' if platform.system().lower() == 'windows' else '-c', '1', host.strip()]
    response = os.system(' '.join(command) + " > /dev/null 2>&1")
    return response == 0  # Returns True if host is reachable

# Function to check if a port is open using telnet (socket)
def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            return result == 0  # Returns True if the port is open
    except:
        return False

# Function to check cipher security using the API
def check_cipher_security(cipher_name):
    url = f"https://ciphersuite.info/api/cs/{cipher_name}/"
    response = requests.get(url)
    
    if response.status_code == 200:
        cipher_data = response.json()
        if cipher_name in cipher_data:
            security_status = cipher_data[cipher_name].get('security', 'unknown')
            return security_status
        else:
            return "Cipher suite information not found"
    else:
        return "Error"

# Function to display the cipher security status
def display_security_status(cipher_name, security_status):
    color_map = {
        'weak': YELLOW,
        'insecure': RED,
        'recommended': BLUE,
        'secure': GREEN
    }
    
    color = color_map.get(security_status.lower(), WHITE)
    return f"{cipher_name} --> {color}{security_status.capitalize()}{RESET}"

# Function to run nmap and parse the output
def run_nmap_ssl_enum(ip, port):
    result = ""
    try:
        result = subprocess.run(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", port, ip],
            capture_output=True,
            text=True
        ).stdout
    except Exception as e:
        print(f"An error occurred while running nmap: {e}")
    
    formatted_output = parse_nmap_output(ip, port, result)
    return formatted_output

# Function to parse nmap output and combine it with security checks
def parse_nmap_output(ip, port, output):
    formatted_output = (
        f"Hosts: {BLUE}{ip}{RESET}\n"
        f"Port: {BLUE}{port}{RESET}\n"
    )

    tls_version_re = re.compile(r"\|\s+(TLSv[0-9]\.[0-9]):")
    cipher_re = re.compile(r"\|\s+([A-Z0-9_]+(?:_[A-Z0-9]+)*)")

    tls_versions = tls_version_re.findall(output)
    ciphers_by_tls = {}

    for tls_version in tls_versions:
        ciphers_by_tls[tls_version] = []

    current_tls = None
    for line in output.splitlines():
        tls_match = tls_version_re.match(line)
        if tls_match:
            current_tls = tls_match.group(1)
        elif current_tls:
            cipher_match = cipher_re.match(line)
            if cipher_match:
                cipher = cipher_match.group(1)
                if "NULL" not in cipher and "64" not in cipher:
                    ciphers_by_tls[current_tls].append(cipher)

    cipher_found = False
    for tls_version, ciphers in ciphers_by_tls.items():
        if ciphers:
            cipher_found = True
            formatted_output += f"\nCiphers:\n"
            formatted_output += f"{tls_version}\n"
            for cipher in ciphers:
                security_status = check_cipher_security(cipher)
                formatted_output += f"{display_security_status(cipher, security_status)}\n"
            formatted_output += "\n"

    if not cipher_found:
        return None

    return formatted_output.strip()

# Main function to process the input file and integrate all functions
def process_ip_port_file(filename):
    if not os.path.isfile(filename):
        print(f"File {filename} not found.")
        return

    try:
        with open(filename, "r") as file:
            for line in file:
                if line.strip():
                    ip_port_pair = line.strip().split()
                    ports = ip_port_pair[0].split(',')
                    ip = ip_port_pair[1]

                    for port in ports:
                        formatted_output = run_nmap_ssl_enum(ip, port)

                        if formatted_output:
                            print(formatted_output + "\n" + "-"*50 + "\n")
                        else:
                            # No ciphers found, check telnet
                            print(f"Hosts: {BLUE}{ip}{RESET}\nPort: {BLUE}{port}{RESET}\nCipher status: No")
                            if not check_port(ip, int(port)):
                                print(f"Telnet: {RED}Port closed{RESET}")
                                if ping_host(ip):
                                    print(f"Ping: {GREEN}Host reachable{RESET}")
                                else:
                                    print(f"Ping: {RED}Host not reachable{RESET}")
                            else:
                                print(f"Telnet: {GREEN}Port open{RESET}")
                            print("\n" + "-"*50 + "\n")

    except Exception as e:
        print(f"An error occurred while processing the file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python combine.py hosts.txt")
        sys.exit(1)
    
    input_filename = sys.argv[1]
    process_ip_port_file(input_filename)
