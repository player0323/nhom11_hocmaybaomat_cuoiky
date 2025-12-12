# -*- coding: utf-8 -*-
import pandas as pd
import features 
import sys
import os
import numpy as np

# INPUT: File d? li?u g?c ch?a URL và nhãn (label)
INPUT_FILE = 'FINAL_DATASET_MERGED_COMPLETE.csv' 
# OUTPUT: File s?ch dùng d? train model
OUTPUT_FILE = 'TRAINING_DATASET_FINAL.csv'

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[LOI] Khong tim thay file {INPUT_FILE}")
        sys.exit()

    print(f"[INFO] Dang doc file {INPUT_FILE}...")
    try:
        df = pd.read_csv(INPUT_FILE)
    except Exception as e:
        print(f"[LOI] Khong doc duoc CSV: {e}")
        sys.exit()
        
    final_data = []
    total = len(df)

    print("[INFO] Bat dau trich xuat dac trung (Feature Extraction)...")

    for index, row in df.iterrows():
        url = str(row['url'])
        label = row['label']
        
        # 1. Static Features (27 dac trung tu features.py)
        # Ham nay tra ve list [f1, f2, ..., f27]
        static_features, _ = features.extract_url_static_features_extended(url)
        
        # 2. Dynamic Features (Lay tu CSV goc hoac gan gia tri mac dinh)
        # Luu y: Trong file goc phai co cot domain_age/ssl_age, neu khong thi gan -1
        domain_age = row.get('domain_age', -1)
        ssl_age = row.get('ssl_age', -1)
        
        if pd.isna(domain_age): domain_age = -1
        if pd.isna(ssl_age): ssl_age = -1
        
        # 3. Logic Combo (Logic giong het app_feature_extractor.py)
        suspicious_age_combo = 0
        domain_bad = (domain_age <= -1) or (0 <= domain_age < 365)
        ssl_bad = (ssl_age <= -1) or (0 <= ssl_age < 30)
        if domain_bad and ssl_bad:
            suspicious_age_combo = 1
        
        # --- GOP VECTOR: 27 Static + 3 Dynamic = 30 Features ---
        feature_vector = static_features + [domain_age, ssl_age, suspicious_age_combo, label]
        
        # Kiem tra do dai vector phai la 31 (30 features + 1 label)
        if len(feature_vector) != 31:
            print(f"[CANH BAO] Dong {index} co do dai sai: {len(feature_vector)}")
            continue

        final_data.append(feature_vector)
        
        if (index + 1) % 1000 == 0: 
            print(f" -> Da xu ly: {index + 1}/{total} dong...")

    # --- DANH SACH TEN COT (PHAI KHOP 100% VOI features.py) ---
    # Thu tu nay duoc anh xa tu ham extract_url_static_features_extended
    cols = [
        # 1. Do dai (6)
        'len_url', 'len_host', 'len_path', 'len_domain', 'len_sub', 'path_level',
        # 2. Ky tu dac biet (10)
        'num_dots', 'num_dash', 'num_dash_host', 'num_at', 'num_tilde', 'num_underscore', 'num_percent', 'num_digits', 'num_ampersand', 'num_hash',
        # 3. Query (2)
        'num_query_comps', 'len_query',
        # 4. Complexity (5)
        'entropy_host', 'entropy_url', 'entropy_sub', 'sub_level', 'sub_sensitive',
        # 5. Logic Static (4)
        'is_shortener', 'double_slash', 'is_typosquatting', 'is_whitelisted', 
        # 6. Dynamic & Logic (3)
        'domain_age', 'ssl_age', 'suspicious_age_combo',
        # LABEL
        'label'                                                                 
    ]

    print(f"[INFO] Luu file {OUTPUT_FILE} voi {len(cols)} cot...")
    df_final = pd.DataFrame(final_data, columns=cols)
    
    # Kiem tra null lan cuoi
    df_final.fillna(0, inplace=True)
    
    df_final.to_csv(OUTPUT_FILE, index=False)
    print(f"[XONG] Da tao dataset moi. Hay chay train_model_final.py ngay!")

if __name__ == "__main__":
    main()