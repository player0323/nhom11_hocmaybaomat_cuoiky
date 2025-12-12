# -*- coding: utf-8 -*-
import features 
import urllib.parse
import tldextract
import whois
import socket
import ssl
from datetime import datetime
import warnings

warnings.filterwarnings("ignore")

def get_realtime_domain_age(url):
    """
    Tinh tuoi Domain (ngay) tu WHOIS.
    Tra ve: so ngay (int) hoac -1 neu loi.
    """
    url_str = str(url).strip()
    full_domain = "Unknown"
    
    try:
        # 1. Trich xuat domain
        if "@" in url_str: return -1
        if not url_str.startswith(('http://', 'https://')): url_str = 'http://' + url_str
        
        ext = tldextract.extract(url_str)
        full_domain = f"{ext.domain}.{ext.suffix}"
        
        if not full_domain or len(ext.domain) < 2: 
            print(f"[DEBUG-AGE] Domain khong hop le: {full_domain}")
            return -1
        
        # 2. Goi WHOIS 
        print(f"[DEBUG-AGE] Dang check WHOIS cho: {full_domain}...")
        try:
            w = whois.whois(full_domain)
        except Exception as e:
            print(f"[DEBUG-AGE] Loi ket noi WHOIS: {e}")
            return -1

        # 3. Lay ngay tao 
        c_date = w.creation_date
        
        # Neu khong co ngay tao
        if not c_date:
            print(f"[DEBUG-AGE] Khong tim thay creation_date cho {full_domain}")
            return -1
            
        # 4. Xu ly dinh dang ngay 
        if isinstance(c_date, list): 
            c_date = c_date[0] # Lay ngay dau tien neu la list
            
        if isinstance(c_date, str):
            # Thu cac dinh dang ngay pho bien
            formats = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y"]
            parsed = False
            for fmt in formats:
                try:
                    c_date = datetime.strptime(c_date.split(' ')[0], fmt)
                    parsed = True
                    break
                except: continue
            if not parsed:
                print(f"[DEBUG-AGE] Khong parse duoc ngay string: {c_date}")
                return -1

        # 5. Tinh toan tuoi
        if c_date:
            if c_date.tzinfo: c_date = c_date.replace(tzinfo=None)
            age = abs((datetime.now() - c_date).days)
            print(f"[DEBUG-AGE] {full_domain} -> Age: {age} days")
            return age
            
    except Exception as e:
        print(f"[DEBUG-AGE] Loi he thong khi check {full_domain}: {e}")
        return -1
        
    return -1

def get_realtime_ssl_age(hostname):
    """
    Tinh tuoi SSL Certificate (ngay).
    """
    if not hostname or "@" in hostname: return -1
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                age = (datetime.utcnow() - not_before).days
                print(f"[DEBUG-SSL] {hostname} -> Age: {age} days")
                return age
    except Exception as e: 
        # print(f"[DEBUG-SSL] Loi SSL check {hostname}: {e}")
        return -1

def extract_features_for_prediction(url):
    """
    Trich xuat vector 30 dac trung cho 1 URL bat ky.
    """
    # Chuan hoa URL
    clean_url = str(url).strip().lower().replace("https://", "").replace("http://", "").replace("www.", "")
    if clean_url.endswith("/"): clean_url = clean_url[:-1]
    input_for_feature = "http://" + clean_url
    
    print(f"[*] Extracting: {input_for_feature}")
    
    # 1. Static Features (27 dac trung)
    static_features, extra_info = features.extract_url_static_features_extended(url)
    
    # Lay hostname
    try:
        ext = tldextract.extract(input_for_feature)
        hostname = f"{ext.domain}.{ext.suffix}"
        if not ext.suffix: hostname = clean_url.split('/')[0]
    except: hostname = clean_url.split('/')[0]

    # 2. Dynamic Features (2 dac trung)
    domain_age = get_realtime_domain_age(input_for_feature)
    ssl_age = get_realtime_ssl_age(hostname)
    
    # 3. Logic Combo (1 dac trung)
    suspicious_age_combo = 0
    domain_bad = (domain_age <= -1) or (0 <= domain_age < 365)
    ssl_bad = (ssl_age <= -1) or (0 <= ssl_age < 30)
    
    if domain_bad and ssl_bad:
        suspicious_age_combo = 1
        
    # --- TONG HOP VECTOR 30 FEATURES ---
    final_vector = static_features + [domain_age, ssl_age, suspicious_age_combo]
    
    print(f"    + Vector size: {len(final_vector)} (Chuan 30)")
    
    extra_info["domain_age"] = domain_age
    extra_info["ssl_age"] = ssl_age
    
    return final_vector, extra_info