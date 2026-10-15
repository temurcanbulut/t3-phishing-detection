from flask import Flask, request, jsonify, render_template
import whois
import ssl
import socket
import requests
import re
from datetime import datetime
import json

app = Flask(__name__)

# Domain geçerliliğini kontrol etme işlemi
def validate_domain(domain):
    domain_pattern = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    return domain_pattern.match(domain) is not None

# güven skoru
def calculate_phishing_score(data):
    score = 100
    
    # SSL sertifikası yoksa 30 puan düşürür
    if not data['ssl_certificate_status']:
        score -= 30

    # Domain yaşı 1 yıldan azsa 20 puan düşürür
    if data['domain_age_days'] < 365:
        score -= 20

    # Domain sıralaması belirli bir değerin üstündeyse 20 puan düşürür
    rank_threshold = 1000000
    if data['domain_rank'] is not None and data['domain_rank'] > rank_threshold:
        score -= 20

    # URL uzunluğu 75 karakterden fazlaysa 10 puan düşürür
    if len(data['domain']) > 75:
        score -= 10

    # URL derinliği 5'ten fazlaysa 10 puan düşürür
    if data['url_depth'] > 5:
        score -= 10

    # URL'de IP adresi varsa 10 puan düşürür
    if data['contains_ip']:
        score -= 10

    # HSTS desteği yoksa 10 puan düşürür
    if not data['hsts_support']:
        score -= 10

    # Google Safe Browsing kötü olarak işaretlediyse 50 puan düşürür
    if data['google_safe_browsing_status']:
        score -= 50

    # Skorun negatif olmaması için minimum değer 0 olarak ayarlanır
    return max(score, 0)

# SSL sertifikası bilgilerini alan fonksiyon
def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issued_to = cert.get('subject', ((('', ''),),))[0][0][1]
                issued_by = cert.get('issuer', ((('', ''),),))[0][0][1]
                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                valid_till = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_to_expiry = (valid_till - datetime.now()).days
                return {
                    'ssl_certificate_status': True,
                    'issued_to': issued_to,
                    'issued_by': issued_by,
                    'valid_from': valid_from.strftime('%Y-%m-%d'),
                    'valid_till': valid_till.strftime('%Y-%m-%d'),
                    'days_to_expiry': days_to_expiry
                }
    except Exception as e:
        # SSL bilgisi alınamazsa durum False olarak döndürülür
        return {
            'ssl_certificate_status': False,
            'error': str(e)
        }

# Domain sıralamasını alan fonksiyon
def get_domain_rank(domain):
    try:
        url = f"https://www.alexa.com/siteinfo/{domain}"
        response = requests.get(url)
        rank = int(re.search(r'Global Rank:</span>\s*<strong>([\d,]+)', response.text).group(1).replace(',', ''))
        return rank
    except Exception as e:
        return None

# HSTS desteği olup olmadığını kontrol eden fonksiyon
def check_hsts_support(domain):
    try:
        response = requests.get(f"https://{domain}")
        return 'strict-transport-security' in response.headers
    except Exception as e:
        return False

# URL'de IP adresi olup olmadığını kontrol eden fonksiyon
def check_ip_in_url(url):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return bool(re.search(ip_pattern, url))

# URL derinliğini hesaplayan fonksiyon
def get_url_depth(url):
    return url.count('/')

# GSB APİ kontrolü
def check_google_safe_browsing(domain):
    try:
        api_key = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
        url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + api_key
        payload = {
            "client": {
                "clientId": "yourcompanyname",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"http://{domain}"}
                ]
            }
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        result = response.json()
        return bool(result.get('matches'))
    except Exception as e:
        return False

# Ana sayfa
@app.route('/')
def index():
    return render_template('index.html')

# Domain kontrolü 
@app.route('/check_domain', methods=['GET'])
def check_domain():
    domain = request.args.get('domain')
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]

    # Domain formatının geçerli olup olmadığını kontrol et
    if not validate_domain(domain):
        return jsonify({'error': 'Geçersiz domain formatı'})

    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
        domain_age_days = (datetime.now() - creation_date).days if creation_date else 0
        ssl_info = get_ssl_info(domain)
        domain_rank = get_domain_rank(domain)
        hsts_support = check_hsts_support(domain)
        url_depth = get_url_depth(request.args.get('domain'))
        contains_ip = check_ip_in_url(request.args.get('domain'))
        google_safe_browsing_status = check_google_safe_browsing(domain)

        data = {
            'domain': domain,
            'domain_age_days': domain_age_days,
            'owner': domain_info.name,
            'owner_email': domain_info.email,
            'domain_rank': domain_rank,
            'hsts_support': hsts_support,
            'url_depth': url_depth,
            'contains_ip': contains_ip,
            'google_safe_browsing_status': google_safe_browsing_status,
            **ssl_info
        }

        # güven skorunu hesapla
        data['score'] = calculate_phishing_score(data)

        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)})

# Uygulama ana fonksiyonu
if __name__ == '__main__':
    app.run(debug=True)
