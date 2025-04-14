import os
import subprocess
import logging
from datetime import datetime
from dotenv import load_dotenv
import config


import re
from netmiko import ConnectHandler

load_dotenv()


netapp_device = {
    'device_type': 'terminal_server',
    'ip': os.getenv('NETAPP_IP'),
    'username': os.getenv('NETAPP_USER'),
    'password': os.getenv('NETAPP_PASSWORD'),
}


print(f"{os.getenv('NETAPP_IP')}\n{os.getenv('NETAPP_USER')}\n{os.getenv('NETAPP_PASSWORD')}")

net_connect = ConnectHandler(**netapp_device)

# Run the CSR generation
output = net_connect.send_command('security certificate generate-csr home.apple.com -algorithm RSA  -hash-function SHA256 -size 4096 -organization apple -unit "big apple"')

# Extract CSR and private key from the output
csr_match = re.search(r'(-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----)', output, re.DOTALL)
key_match = re.search(r'(-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)', output, re.DOTALL)

if csr_match and key_match:
    csr = csr_match.group(1)
    key = key_match.group(1)

    # Save to files
    with open("home.apple.csr", "w") as csr_file:
        csr_file.write(csr + "\n")

    with open("home.apple.key", "w") as key_file:
        key_file.write(key + "\n")

    print("[+] CSR and key saved to files.")
else:
    print("[-] Failed to parse CSR or private key.")

net_connect.disconnect()
