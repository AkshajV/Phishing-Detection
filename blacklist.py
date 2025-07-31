import hashlib
import os
import email
from bs4 import BeautifulSoup
import re
import json
import requests
from urllib.parse import urlparse, quote
from urlextract import URLExtract
import pandas as pd
import joblib
# Import the custom classes from the separate file to avoid retraining
from model_classes import SenderPatternFeatures, URLFeatureExtractor

EML_DIR = 'emails/'
WHITELIST_FILE = 'whitelist.json'
PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
USER_AGENT = "phishtank/PhishDet"
# Remove the hardcoded API key
PHISHTANK_API_KEY = ""  # Add your API key here if you have one

# Add this for VirusTotal
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/"

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

    return from_addr, subject, body, urls, msg

def extract_attachments(msg, save_dir='attachments'):
    attachments = []
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue

        filename = part.get_filename()
        if filename:
            # Clean filename to avoid path issues
            safe_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
            filepath = os.path.join(save_dir, safe_filename)
            try:
                with open(filepath, "wb") as f:
                    f.write(part.get_payload(decode=True))
                attachments.append(filepath)
            except Exception as e:
                print(f"⚠️ Error saving attachment {filename}: {e}")
    return attachments

def get_file_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_virustotal(file_hash):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    url = VIRUSTOTAL_URL + file_hash
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious_count = stats.get('malicious', 0)
            if malicious_count > 0:
                return 'malicious'
            else:
                return 'safe'
        elif response.status_code == 404:
            return 'unknown'  # File not found in VT database
        else:
            print(f"⚠️ VirusTotal API error: {response.status_code}")
            return 'unknown'
    except Exception as e:
        print(f"⚠️ Error checking VirusTotal: {e}")
        return 'unknown'

def ml_detection_check(from_addr, subject, body, urls):
    """
    Use ML model to detect phishing emails when blacklist checks fail
    """
    try:
        # Load the trained model
        model = joblib.load("phishing_email_model_fixed.pkl")
        
        # Prepare data for ML model
        email_data = {
            'subject': subject,
            'body': body,
            'sender': from_addr,
            'urls': len(urls)
        }
        
        # Create DataFrame for prediction
        test_df = pd.DataFrame([email_data])
        
        # Make prediction
        prediction = model.predict(test_df)[0]
        prediction_proba = model.predict_proba(test_df)[0]
        confidence = max(prediction_proba) * 100
        
        # Determine result
        result = "PHISHING" if prediction == 1 else "LEGITIMATE"
        
        return result, confidence
        
    except Exception as e:
        print(f"⚠️ Error in ML detection: {e}")
        return "ERROR", 0

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
                from_addr, subject, body, urls, msg = parse_emails(filepath)
                print(f"📧 File: {eml_file}")
                print(f"From: {from_addr}")
                print(f"Subject: {subject}")
                
                # Track overall email status
                email_status = "SAFE"
                blacklist_failed = False
                
                print("🔍 BLACKLIST ANALYSIS:")
                print("Extracted URLs:")
                for url in urls:
                    print(f"  - {url}")
                    if is_whitelisted(url, whitelist):
                        print("    ✅ Whitelisted — skipping analysis.")
                        continue
                    status = check_phishtank(url)
                    if status == 'malicious':
                        print("    ⚠️ Malicious URL detected!")
                        email_status = "MALICIOUS"
                    elif status == 'safe':
                        print("    ✅ URL is safe.")
                    else:
                        print("    ⚠️ Unknown status.")
                        blacklist_failed = True
                
                # --- Attachment checking ---
                attachments = extract_attachments(msg)
                if attachments:
                    print("Attachments found:")
                    for attachment in attachments:
                        file_hash = get_file_sha256(attachment)
                        status = check_virustotal(file_hash)
                        if status == 'malicious':
                            print(f"  ⚠️ Malicious attachment detected: {attachment}")
                            email_status = "MALICIOUS"
                        elif status == 'safe':
                            print(f"  ✅ Attachment is safe: {attachment}")
                        else:
                            print(f"  ⚠️ File Not Found in VirusTotal Database (Unknown): {attachment}")
                            blacklist_failed = True
                else:
                    print("No attachments found.")
                
                # --- ML Detection as Fallback ---
                if email_status != "MALICIOUS" and blacklist_failed:
                    print("\n🤖 ML DETECTION (Fallback):")
                    ml_result, confidence = ml_detection_check(from_addr, subject, body, urls)
                    if ml_result == "PHISHING":
                        print(f"    ⚠️ ML Model detected PHISHING (Confidence: {confidence:.2f}%)")
                        email_status = "MALICIOUS"
                    elif ml_result == "LEGITIMATE":
                        print(f"    ✅ ML Model detected LEGITIMATE (Confidence: {confidence:.2f}%)")
                    else:
                        print(f"    ⚠️ ML detection error")
                
                # Final verdict
                print(f"\n🎯 FINAL VERDICT: {email_status}")
                if email_status == "MALICIOUS":
                    print("    🚨 EMAIL IS MALICIOUS - TAKE ACTION!")
                else:
                    print("    ✅ Email appears to be safe")
                
                print("\n" + "-"*60 + "\n")

