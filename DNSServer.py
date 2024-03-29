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

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))  # call the Fernet encrypt method
    return encrypted_data    

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)  # call the Fernet decrypt method
    return decrypted_data.decode('utf-8')

salt = b'Tandon'  # Remember it should be a byte-object
password = 'your_nyu_email@nyu.edu'  # Replace with your actual NYU email
input_string = 'AlwaysWatching'

encrypted_value = encrypt_with_aes(input_string, password, salt)  # exfil function

dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101'
    },
    'safebank.com.': {'A': '192.168.1.102'},
    'google.com.': {'A': '192.168.1.103'},
    'legitsite.com.': {'A': '192.168.1.104'},
    'yahoo.com.': {'A': '192.168.1.105'},
    'nyu.edu.': {
        'A': '192.168.1.106',
        'TXT': str(encrypted_value.decode('utf-8')),  # Encrypt the secret data
        'MX': [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        'AAAA': '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        'NS': 'ns1.nyu.edu.'
    }
}

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use SOCK_DGRAM for UDP
    server_socket.bind(('0.0.0.0', 53))  # Bind to 0.0.0.0:53, the standard port for DNS

    while True:
        try:
            data, addr = server_socket.recvfrom(512)
            request = dns.message.from_wire(data)
            response = request.make_response()

            if request.question:
                question = request.question[0]
                qname = question.name.to_text()
                qtype = question.rdtype

                if qname in dns_records and qtype in dns_records[qname]:
                    answer_data = dns_records[qname][qtype]

                    if qtype == dns.rdatatype.MX:
                        for pref, server in answer_data:
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, dns.rdatatype.MX, f'{pref} {server}'))
                    elif qtype == dns.rdatatype.TXT:
                        response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, dns.rdatatype.TXT, answer_data))
                    else:
                        response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, answer_data))

                    response.flags |= dns.flags.AA

            server_socket.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

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
