import email
from bs4 import BeautifulSoup
import re
import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv('VT_APIKEY')

def check_urls_with_virustotal(urls):
    headers = {"x-apikey": VT_API_KEY}
    for url in urls:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls", headers=headers)
        if response.status_code != 200:
            continue
        data = {"url": url}
        scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        if scan_response.status_code != 200:
            continue
        scan_result = scan_response.json()
        analysis_id = scan_result['data']['id']
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        report_json = report.json()
        stats = report_json['data']['attributes']['stats']
        if stats['malicious'] > 0:
            return "Phishing (based on URL)"
    return "Legitimate (no malicious URLs)"


def parse_eml(eml_file):
    with open(eml_file, 'rb') as efile:
        eml_bytes = efile.read()

    msg = email.message_from_bytes(eml_bytes)
    subject = msg.get('Subject', '')
    sender = msg.get('From', '')
    msg_id = msg.get('Message-ID', '')
    date = msg.get('Date', '')
    payload = ''
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                try:
                    payload = part.get_payload(decode=True).decode(errors="ignore")
                    break
                except:
                    continue
    else:
        payload = msg.get_payload(decode=True).decode(errors="ignore")

    soup = BeautifulSoup(payload, "html.parser")
    body_text = soup.get_text()
    urls = re.findall(r'https?://\S+', payload)
    spf_result = msg.get('Received-SPF', 'Not Available')
    auth_results = msg.get('Authentication-Results', '')
    dmarc_match = re.search(r'dmarc=(\w+)', auth_results.lower())
    dmarc_result = dmarc_match.group(1).upper() if dmarc_match else 'Not Available'
    return {
        'message_id': msg_id,
        'date': date,
        'subject': subject,
        'sender': sender,
        'body_text': body_text,
        'urls': urls,
        'spf': spf_result,
        'dmarc': dmarc_result
    }