import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdata
from dns.rdtypes.IN.MX import MX
from dns.rdtypes.ANY.SOA import SOA
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

encrypted_value = encrypt_with_aes(input_string, password, salt)  # exfil function

def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()


# DNS records setup
dns_records = {
    'safebank.com.': {'A': '192.168.1.102'},
    'google.com.': {'A': '192.168.1.103'},
    'legitsite.com.': {'A': '192.168.1.104'},
    'yahoo.com.': {'A': '192.168.1.105'},
    'nyu.edu.': {
        'A': '192.168.1.106',
        'TXT': [encrypted_value.decode('utf-8')],
        'MX': [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        'AAAA': '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        'NS': 'ns1.nyu.edu.'
    }
}

# Function to run DNS server
def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 53))  # Bind to all interfaces for broader accessibility

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)

            # Initialize response with default values
            response = dns.message.Message()
            response.id = request.id
            response.flags = dns.flags.QR | dns.flags.AA | dns.flags.RD
            response.set_opcode(dns.opcode.QUERY)
            response.set_rcode(0)

            if request.question:
                question = request.question[0]
                qname = question.name.to_text()
                qtype = question.rdtype

                # Logging for debugging
                print(f"Handling query for {qname} of type {qtype}")

                if qname in dns_records and qtype in dns_records[qname]:
                    answer_data = dns_records[qname][qtype]

                    for rdata in answer_data:
                        if qtype == dns.rdatatype.MX:
                            preference, exchange = rdata
                            mx_record = MX(dns.rdataclass.IN, qtype, preference=preference, exchange=dns.name.from_text(exchange))
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, mx_record.to_text()))
                        elif qtype == dns.rdatatype.SOA:
                            mname, rname, serial, refresh, retry, expire, minimum = answer_data
                            soa_record = SOA(dns.rdataclass.IN, qtype, mname=dns.name.from_text(mname), rname=dns.name.from_text(rname), serial=serial, refresh=refresh, retry=retry, expire=expire, minimum=minimum)
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, soa_record.to_text()))
                        else:
                            # General handling for A, AAAA, NS, TXT
                            record = dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data if isinstance(answer_data, str) else ' '.join(answer_data))
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, record.to_text()))

                server_socket.sendto(response.to_wire(), addr)
                print(f"Response sent for {qname}")
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            break





if __name__ == '__main__':
    run_dns_server_user()
    #print("Encrypted Value:", encrypted_value)
    #print("Decrypted Value:", decrypted_value)
