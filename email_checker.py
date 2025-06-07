import os
import email
from bs4 import BeautifulSoup
import re
import json
import requests
from urllib.parse import urlparse, quote
from urlextract import URLExtract

EML_DIR = 'emails/'
WHITELIST_FILE = 'whitelist.json'
PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
USER_AGENT = "phishtank/PhishDet"
PHISHTANK_API_KEY = ""  # Add your API key here if you have one

def load_whitelist(filepath):
    with open(filepath, 'r') as f:
        whitelist = json.load(f)
    return whitelist

def is_whitelisted(url, whitelist):
    parsed = urlparse(url)
    domain = parsed.netloc

    # Exact URL match
    if url in whitelist.get('exactMatching', {}).get('url', []):
        return True

    # Domain matches
    for whitelisted_domain in whitelist.get('exactMatching', {}).get('domain', []):
        if whitelisted_domain in domain:
            return True

    # Domains in URLs
    for domain_substring in whitelist.get('domainsInURLs', []):
        if domain_substring in domain:
            return True

    return False

def check_phishtank(url):
    headers = {'User-Agent': USER_AGENT}
    payload = {
        'url': url,  # Do NOT encode with quote()
        'format': 'json'
    }
    if PHISHTANK_API_KEY:
        payload['app_key'] = PHISHTANK_API_KEY

    try:
        response = requests.post(PHISHTANK_API_URL, data=payload, headers=headers, timeout=10)
        print(f"Querying PhishTank for: {url}")
        print(f"Status code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"PhishTank response: {data}")
            results = data.get('results', {})
            in_database = results.get('in_database', False)
            verified = results.get('verified', False)
            valid = results.get('valid', False)

            if in_database and verified and valid:
                return 'malicious'
            elif in_database and not verified:
                return 'suspicious'
            else:
                return 'safe'
        else:
            print(f"⚠️ API call failed: {response.status_code}")
            return 'unknown'
    except Exception as e:
        print(f"⚠️ Error querying PhishTank: {e}")
        return 'unknown'

def parse_emails(filepath):
    with open(filepath, 'rb') as f:
        raw_email = f.read()
    
    msg = email.message_from_bytes(raw_email)

    #Extract subject
    subject_header = msg['Subject']
    if subject_header:
        subject_decoded = email.header.decode_header(subject_header)
        subject = ''
        for fragment, encoding in subject_decoded:
            if isinstance(fragment, bytes):
                subject += fragment.decode(encoding or 'utf-8', errors='replace')
            else:
                subject += fragment
    else:
        subject = '(No Subject)'

    #extract from address
    from_addr = email.utils.parseaddr(msg.get('From'))[1]

    #Extract body
    body = ''
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain':
            try:
                body += part.get_payload(decode=True).decode(errors='replace')
            except:
                continue
        elif content_type == 'text/html':
            try:
                html = part.get_payload(decode=True).decode(errors='replace')
                soup = BeautifulSoup(html, 'html.parser')
                body += soup.get_text()
            except:
                continue
    
    # Extract URLs using regex
    extractor = URLExtract()
    urls = extractor.find_urls(body)

    return from_addr, subject, body, urls

if __name__ == '__main__':
    whitelist = load_whitelist(WHITELIST_FILE)

    # Check for .eml files in the directory
    if not os.path.exists(EML_DIR):
        print(f"📁 Directory '{EML_DIR}' does not exist. Please create it and add your .eml files.")
    else:
        eml_files = [f for f in os.listdir(EML_DIR) if f.endswith('.eml')]
        if not eml_files:
            print(f"⚠️ No .eml files found in '{EML_DIR}'. Please add some emails for analysis.")
        else:
            for eml_file in eml_files:
                filepath = os.path.join(EML_DIR, eml_file)
                from_addr, subject, body, urls = parse_emails(filepath)
                print(f"📧 File: {eml_file}")
                print(f"From: {from_addr}")
                print(f"Subject: {subject}")
                print("Extracted URLs:")
                for url in urls:
                    print(f"  - {url}")
                    if is_whitelisted(url, whitelist):
                        print("    ✅ Whitelisted — skipping analysis.")
                        continue
                    status = check_phishtank(url)
                    if status == 'malicious':
                        print("    ⚠️ Malicious URL detected!")
                    elif status == 'safe':
                        print("    ✅ URL is safe.")
                    else:
                        print("    ⚠️ Unknown status.")
                print("\n" + "-"*60 + "\n")

