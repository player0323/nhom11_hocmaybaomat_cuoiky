# -*- coding: utf-8 -*-
import urllib.parse
import tldextract
import math
import difflib
import re
import os
import csv

# =============================================================================
# CAU HINH
# =============================================================================
TRANCO_CSV_PATH = 'final_whitelist.csv'
SAFE_DOMAINS_SET = set()

SENSITIVE_BRANDS = [
    'facebook', 'google', 'youtube', 'amazon', 'apple', 'paypal', 'microsoft', 'instagram', 'netflix', 'whatsapp',
    'twitter', 'linkedin', 'dropbox', 'ebay', 'binance', 'coinbase', 'blockchain',
    'mbbank', 'vietcombank', 'techcombank', 'acb', 'sacombank', 'bidv', 'agribank', 'vpbank', 'tpbank',
    'shopee', 'lazada', 'tiki', 'zalo', 'momo', 'zalopay', 'vnpay',
    'adobe', 'icloud', 'outlook', 'hotmail', 'yahoo', 'support', 'secure', 'account', 'login'
]

SHORTENING_SERVICES = [
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly", "adf.ly", "bit.do", 
    "mcaf.ee", "su.pr", "google.com/url", "short.gy", "v.gd", "shorte.st", "go2l.ink", "x.co", 
    "tr.im", "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac"
]

def load_tranco_list():
    global SAFE_DOMAINS_SET
    
    if os.path.exists(TRANCO_CSV_PATH):
        try:
            with open(TRANCO_CSV_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                line1 = f.readline()
                if "origin" not in line1.lower() and "domain" not in line1.lower(): f.seek(0)
                
                for line in f:
                    clean_domain = line.strip()
                    if clean_domain:
                        #  WHITELIST
                        SAFE_DOMAINS_SET.add(clean_domain)
                        
            print(f"[INIT] Da load {len(SAFE_DOMAINS_SET)} Whitelist. Typosquatting chi check {len(SENSITIVE_BRANDS)} Brand cung.")
        except Exception as e: print(f"[LOI] {e}")
    else: print("[CANH BAO] Khong tim thay file final_whitelist.csv")

load_tranco_list()

# =============================================================================
# HAM HO TRO
# =============================================================================
def normalize_leet_speak(text):
    replacements = {'@': 'a', '4': 'a', '^': 'a', '0': 'o', '()': 'o', '.': '', '3': 'e', '1': 'l', '!': 'i', '|': 'l', '$': 's', '5': 's'}
    normalized = text.lower()
    for k, v in replacements.items(): normalized = normalized.replace(k, v)
    return normalized

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2): return levenshtein_distance(s2, s1)
    if len(s2) == 0: return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in set(text): p_x = text.count(x) / len(text); entropy += - p_x * math.log2(p_x)
    return entropy

def extract_visual_body(clean_url):
    try:
        domain_part = clean_url.split('/')[0]
        if '.' in domain_part:
            body = domain_part.rsplit('.', 1)[0]
            if '.' in body: body = body.rsplit('.', 1)[0]
            return body
        return domain_part
    except: return clean_url

def check_shortener(full_domain):
    if not full_domain: return 0
    for s in SHORTENING_SERVICES:
        if s in full_domain: return 1
    return 0

# =============================================================================
# HAM CHECK LOGIC 
# =============================================================================
def check_status_logic(domain_body, full_domain, clean_url):
    is_white = 0
    is_typo = 0
    typo_msg = None
    domain_part = clean_url.split('/')[0]
    
    # 1. Whitelist (Check Root)
    if domain_part in SAFE_DOMAINS_SET: 
        return 1, 0, None 
        
    try:
        ext_check = tldextract.extract("http://" + domain_part)
        root_check = f"{ext_check.domain}.{ext_check.suffix}"
        if root_check in SAFE_DOMAINS_SET:
            return 1, 0, None
    except: pass

    # 2. Typosquatting (SENSITIVE_BRANDS)
    try:
        raw_body = extract_visual_body(clean_url)
        decoded_part = normalize_leet_speak(raw_body)
        
        for brand in SENSITIVE_BRANDS:
            # A. Leet Speak: Giong Brand NHUNG chu goc KHAC Brand
            if decoded_part == brand and raw_body != brand:
                return 0, 1, f"Gia mao '{brand}' (Leet Speak)"
            
            # B. Levenshtein: Sai 1-2 ky tu
            dist = levenshtein_distance(decoded_part, brand)
            if dist > 0 and dist <= 2:
                # Tranh bat nham brand ngan (duoi 4 ky tu)
                if len(brand) < 4: continue
                return 0, 1, f"Gia mao '{brand}' (Levenshtein: {dist})"
            
    except: pass
    
    return 0, 0, None

# =============================================================================
# HAM TRICH XUAT STATIC (27 FEATURES)
# =============================================================================
def extract_url_static_features_extended(url):
    features = []
    url_str = str(url).strip()
    clean_url = url_str.lower().replace("https://", "").replace("http://", "").replace("www.", "")
    if clean_url.endswith("/"): clean_url = clean_url[:-1]
    input_for_parse = "http://" + clean_url

    try:
        parsed = urllib.parse.urlparse(input_for_parse)
        ext = tldextract.extract(input_for_parse)
        domain_body = ext.domain
        full_domain = f"{ext.domain}.{ext.suffix}"
        subdomain = ext.subdomain
    except: return [0]*27, {}

    # --- NHOM 1: DO DAI (6) ---
    features.append(len(input_for_parse)); features.append(len(parsed.netloc)); features.append(len(parsed.path))
    features.append(len(domain_body)); features.append(len(subdomain) if subdomain else 0)
    features.append(len(parsed.path.split('/')) - 1 if parsed.path else 0) # PathLevel

    # --- NHOM 2: KY TU (10) ---
    features.append(input_for_parse.count('.')); features.append(input_for_parse.count('-'))
    features.append(parsed.netloc.count('-'))   # NumDashInHostname
    features.append(input_for_parse.count('@')); features.append(input_for_parse.count('~'))
    features.append(input_for_parse.count('_')); features.append(input_for_parse.count('%'))
    features.append(sum(c.isdigit() for c in input_for_parse)); features.append(input_for_parse.count('&'))
    features.append(input_for_parse.count('#')) # NumHash

    # --- NHOM 3: QUERY (2) ---
    query_comps = len(parsed.query.split('&')) if parsed.query else 0
    features.append(query_comps)
    features.append(len(parsed.query))

    # --- NHOM 4: COMPLEXITY (5) ---
    features.append(calculate_entropy(parsed.netloc)); features.append(calculate_entropy(input_for_parse))
    features.append(calculate_entropy(subdomain))
    features.append(subdomain.count('.') + 1 if subdomain else 0)
    sens = ['login', 'secure', 'account', 'verify', 'update', 'banking', 'confirm']
    features.append(1 if any(w in subdomain for w in sens) else 0)
    
    # --- NHOM 5: LOGIC (4) ---
    features.append(check_shortener(full_domain))       # 24. Is Shortener
    features.append(1 if '//' in parsed.path else 0)    # 25. Double Slash
    
    is_white, is_typo, typo_msg = check_status_logic(domain_body, full_domain, clean_url)
    features.append(is_typo)                      # 26. Is Typosquatting
    features.append(is_white)                     # 27. Is Whitelist

    return features, {"is_whitelisted": is_white, "typo_msg": typo_msg}