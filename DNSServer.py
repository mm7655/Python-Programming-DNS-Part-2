import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

# Encryption and decryption utilities
def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    return f.encrypt(input_string.encode('utf-8'))

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode('utf-8')

# Prepare encryption parameters
salt = b'Tandon'
password = 'mm7655@nyu.edu'  # Replace with your actual NYU email
input_string = 'AlwaysWatching'

encrypted_value = encrypt_with_aes(input_string, password, salt)  # exfil function

# DNS records setup
dns_records = {
    'safebank.com.': {dns.rdatatype.A: '192.168.1.102'},
    'google.com.': {dns.rdatatype.A: '192.168.1.103'},
    'legitsite.com.': {dns.rdatatype.A: '192.168.1.104'},
    'yahoo.com.': {dns.rdatatype.A: '192.168.1.105'},
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value.decode('utf-8')),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.'
    }
}

# Function to run DNS server
def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))  # Use localhost for testing

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            if request.question:
                question = request.question[0]
                qname = question.name.to_text()
                qtype = question.rdtype

                if qname in dns_records and qtype in dns_records[qname]:
                    answer_data = dns_records[qname][qtype]

#                    if qtype == dns.rdatatype.MX:
#                        for pref, server in answer_data:
#                            mx_rdata = MX(dns.rdataclass.IN, dns.rdatatype.MX, preference=pref, exchange=dns.name.from_text(server))
#                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, mx_rdata.to_text()))

                                    # Append A records
                    if qtype == dns.rdatatype.A:
                        for ip in answer_data:
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, dns.rdatatype.A, ip))
                    
                    # Append AAAA records
                    elif qtype == dns.rdatatype.AAAA:
                        for ip in answer_data:
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, dns.rdatatype.AAAA, ip))
                    
                    # Append TXT records
                    elif qtype == dns.rdatatype.TXT:
                        # Ensure TXT data is a list, even if only one value
                        if isinstance(answer_data, str):
                            answer_data = [answer_data]
                        for txt in answer_data:
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, dns.rdatatype.TXT, f'"{txt}"'))

                    # Append NS records
                    elif qtype == dns.rdatatype.NS:
                        for ns in answer_data:
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, dns.rdatatype.NS, ns))

                    # Append MX records
                    elif qtype == dns.rdatatype.MX:
                        for pref, server in answer_data:
                            mx_rdata = MX(dns.rdataclass.IN, dns.rdatatype.MX, preference=pref, exchange=dns.name.from_text(server))
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, mx_rdata.to_text()))



                # Send the response back to the client
                server_socket.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

# User input handling for graceful shutdown
def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
