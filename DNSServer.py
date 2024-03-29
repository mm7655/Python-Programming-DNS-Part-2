import dns.message
import dns.rdatatype
import dns.rdataclass
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

encrypted_value = encrypt_with_aes(input_string, password, salt) # exfil function
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # exfil function

def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()


# DNS records setup
dns_records = {
    'safebank.com.': {dns.rdatatype.A: '192.168.1.102'},
    'google.com.': {dns.rdatatype.A: '192.168.1.103'},
    'legitsite.com.': {dns.rdatatype.A: '192.168.1.104'},
    'yahoo.com.': {dns.rdatatype.A: '192.168.1.105'},
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: [encrypted_value.decode('utf-8')],
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.'
    }
}

# Function to run DNS server
def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(512)
            request = dns.message.from_wire(data)

            response = dns.message.Message()
            response.id = request.id
            response.flags = dns.flags.QR | dns.flags.AA | dns.flags.RD
            response.set_opcode(dns.opcode.QUERY)
            response.set_rcode(0)  # No error

            if request.question:
                question = request.question[0]
                qname = question.name.to_text()
                qtype = question.rdtype

                if qname in dns_records and qtype in dns_records[qname]:
                    record_data = dns_records[qname][qtype]
                    if isinstance(record_data, list):  # For TXT and MX records which are lists
                        for item in record_data:
                            if qtype == dns.rdatatype.MX:
                                preference, exchange = item
                                rd = dns.rdata.from_text(dns.rdataclass.IN, qtype, f'{preference} {exchange}')
                            else:  # For TXT records
                                rd = dns.rdata.from_text(dns.rdataclass.IN, qtype, item)
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, rd.to_text()))
                    else:  # For A, AAAA, NS records which are single strings
                        rd = dns.rdata.from_text(dns.rdataclass.IN, qtype, record_data)
                        response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, rd.to_text()))

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
            if cmd.lower
