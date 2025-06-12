#!/usr/bin/env python3
import sys
import os
import sqlite3
import requests
import time
import csv
from io import StringIO
import argparse

CACHE_DB = 'ip_cache.sqlite'
API_URL = 'http://ip-api.com/json/'
API_FIELDS = 'status,message,city,regionName,country'
SLEEP_BETWEEN_REQUESTS = 1  # seconds, to be polite to the API


def get_input_ips():
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            lines = f.read().splitlines()
    else:
        lines = sys.stdin.read().splitlines()
    return lines


def init_db():
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ip_cache (
        ip TEXT PRIMARY KEY,
        location TEXT,
        last_lookup INTEGER
    )''')
    conn.commit()
    return conn


def get_cached_location(conn, ip):
    c = conn.cursor()
    c.execute('SELECT location FROM ip_cache WHERE ip = ?', (ip,))
    row = c.fetchone()
    return row[0] if row else None


def cache_location(conn, ip, location):
    c = conn.cursor()
    c.execute('REPLACE INTO ip_cache (ip, location, last_lookup) VALUES (?, ?, ?)',
              (ip, location, int(time.time())))
    conn.commit()


def lookup_ip(ip):
    try:
        resp = requests.get(f'{API_URL}{ip}?fields={API_FIELDS}', timeout=5)
        data = resp.json()
        if data.get('status') == 'success':
            city = data.get('city')
            region = data.get('regionName')
            country = data.get('country')
            # Compose location string
            location = ', '.join(filter(None, [city, region, country]))
            return location if location else 'Unknown'
        else:
            return f"Error: {data.get('message', 'Unknown error')}"
    except Exception as e:
        return f"Error: {e}"


def csv_escape(value):
    """Escape a value for CSV output as a single field (wrap in quotes if needed)."""
    sio = StringIO()
    writer = csv.writer(sio, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([value])
    return sio.getvalue().strip('\r\n')


def tsv_escape(value):
    """Escape a value for TSV output: quote if it contains tab, quote, or newline, and double quotes inside."""
    if any(c in value for c in ['\t', '\n', '"']):
        return '"' + value.replace('"', '""') + '"'
    return value


def main():
    parser = argparse.ArgumentParser(description="IP to region lookup tool.")
    parser.add_argument('filename', nargs='?', help='Input file (default: stdin)')
    parser.add_argument('--tsv', action='store_true', help='Output tab-delimited (TSV) instead of CSV')
    args = parser.parse_args()

    output_is_pipe = not sys.stdout.isatty()
    if output_is_pipe:
        sys.stderr.write("[ip_region_lookup] Starting lookup...\n")
        sys.stderr.flush()

    if args.filename:
        with open(args.filename, 'r') as f:
            ips = f.read().splitlines()
    else:
        ips = sys.stdin.read().splitlines()

    unique_ips = list({ip for ip in ips if ip.strip()})
    conn = init_db()
    ip_to_location = {}

    for ip in unique_ips:
        ip = ip.strip()
        if not ip:
            continue
        cached = get_cached_location(conn, ip)
        if cached is not None:
            ip_to_location[ip] = cached
        else:
            if output_is_pipe:
                sys.stderr.write(f"[ip_region_lookup] Looking up IP: {ip}\n")
                sys.stderr.flush()
            location = lookup_ip(ip)
            cache_location(conn, ip, location)
            ip_to_location[ip] = location
            time.sleep(SLEEP_BETWEEN_REQUESTS)

    for ip in ips:
        ip_stripped = ip.strip()
        if not ip_stripped:
            print('\t' if args.tsv else ',')
        else:
            location = ip_to_location.get(ip_stripped, "Unknown")
            if args.tsv:
                print(f'{ip}\t{tsv_escape(location)}')
            else:
                print(f'{ip},{csv_escape(location)}')

if __name__ == '__main__':
    main() 