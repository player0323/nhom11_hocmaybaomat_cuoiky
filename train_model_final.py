# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
import joblib
import os
import time
import matplotlib.pyplot as plt
import seaborn as sns
import warnings

# Sklearn & Imblearn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline
# [UPDATE] Them precision_score va recall_score vao import
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from imblearn.over_sampling import SMOTE

warnings.filterwarnings('ignore')
pd.set_option('display.max_columns', None)
sns.set(style="whitegrid")

INPUT_FILE = 'TRAINING_DATASET_FINAL.csv'
MODEL_OUTPUT = 'phishing_model_final.pkl'
SCALER_OUTPUT = 'scaler.pkl'
LIST_OUTPUT = 'feature_list.pkl'


# =============================================================================
# 1. LOAD & PHAN TICH
# =============================================================================
def load_and_analyze():
    print("\n--- [1] DOC DU LIEU ---")
    if not os.path.exists(INPUT_FILE):
        print(f" Loi: Khong tim thay {INPUT_FILE}")
        exit()

    df = pd.read_csv(INPUT_FILE)
    print(f"   Shape: {df.shape}")
    # Xử lý dữ liệu thiếu 
    if df.isnull().sum().sum() > 0:
        df.fillna(-1, inplace=True)

    X = df.drop(columns=['label'])
    y = df['label']
    print("Phân bố nhãn gốc:")
    print(y.value_counts())

    print("\n--- [2] PHAN TICH DAC TRUNG (FEATURE IMPORTANCE) ---")
    rf_temp = RandomForestClassifier(n_estimators=50, n_jobs=-1, random_state=42)
    rf_temp.fit(X, y)

    importances = pd.DataFrame({
        'Feature': X.columns,
        'Importance': rf_temp.feature_importances_
    }).sort_values(by='Importance', ascending=False)

    print(importances.head(10).to_string(index=False))

    plt.figure(figsize=(12, 6))
    sns.barplot(x='Importance', y='Feature', data=importances.head(15), palette='viridis')
    plt.title('Top 15 Feature Importance')
    plt.tight_layout()
    # plt.savefig('analysis_feature_importance.png') # Uncomment neu muon luu anh
    plt.show() 

    return X, y


# =============================================================================
# 2. TIEN XU LY + SMOTE
# =============================================================================
def process_data(X, y):
    print("\n--- [3] TIEN XU LY ---")

    feature_names = list(X.columns)
    joblib.dump(feature_names, LIST_OUTPUT)
    print(f"   -> Saved feature list.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print("   -> SMOTE balancing...")
    sm = SMOTE(random_state=42)
    X_train_bal, y_train_bal = sm.fit_resample(X_train, y_train)

    # Scaler se duoc fit trong pipeline, nhung o day ta scale thu cong de tra ve neu can
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_bal)
    X_test_scaled = scaler.transform(X_test)

    joblib.dump(scaler, SCALER_OUTPUT)

    return X_train_bal, y_train_bal, X_train_scaled, X_test, X_test_scaled, y_test


# =============================================================================
# 3. TRAIN 3 MODEL
# =============================================================================
def train_models(X_train_bal, y_train_bal, X_train_scaled, X_test, X_test_scaled, y_test):
    print("\n--- [4] HUAN LUYEN 3 MODEL ---")

    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=5000, random_state=42),
        "SVM": SVC(kernel='linear', probability=True, random_state=42)
    }

    best_f1 = -1
    best_model = None
    best_name = None
    summary_data = [] # [UPDATE] Khoi tao list luu ket qua

    for name, model in models.items():
        print(f"\nTraining {name}...")

        # Setup Pipeline
        scaler = StandardScaler()
        pipe = Pipeline([
            ("scaler", scaler),
            ("estimator", model)
        ])
        
        # [UPDATE] Do thoi gian huan luyen
        start_time = time.time()
        pipe.fit(X_train_bal, y_train_bal)
        training_time = time.time() - start_time
        
        y_pred = pipe.predict(X_test)

        # Luu rieng tung model
        joblib.dump(pipe, f"model_{name.lower().replace(' ', '_')}.pkl")
        
        # Tính toán các chỉ số
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        print(f"Thời gian huấn luyện: {training_time:.4f} giây")
        print(f"Accuracy: {acc:.4f} | F1-Score: {f1:.4f}")
        
        # Lưu vào bảng tổng hợp
        summary_data.append({
            "Model": name,
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "Time (s)": training_time
        })
        
        # Vẽ Ma trận nhầm lẫn 
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                    xticklabels=['An toàn (0)', 'Độc hại (1)'],
                    yticklabels=['An toàn (0)', 'Độc hại (1)'])
        plt.title(f'Confusion Matrix: {name}\n(Accuracy: {acc:.2%})', fontsize=14)
        plt.xlabel('Dự đoán', fontsize=12)
        plt.ylabel('Thực tế', fontsize=12)
        plt.show() # Hiển thị ngay
        
        # Kiểm tra model tốt nhất
        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_model = pipe # Luu ca pipeline
            
            # Lưu scaler nếu cần (Code cu cua ban yeu cau)
            # Trong pipeline da co scaler, nhung van luu rieng theo logic cua ban
            if name != "Random Forest":
                joblib.dump(scaler, 'scaler.pkl')

    # Hien thi bang tong hop ket qua ra man hinh
    print("\n--- KET QUA TONG HOP ---")
    summary_df = pd.DataFrame(summary_data)
    print(summary_df.to_string(index=False))

    print(f"\nBEST MODEL: {best_name} (F1={best_f1:.4f})")
    joblib.dump(best_model, MODEL_OUTPUT)

    return best_model, best_name


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    # 1. Load & Analyze
    X, y = load_and_analyze()
    
    # 2. Process
    X_train_bal, y_train_bal, X_train_scaled, X_test, X_test_scaled, y_test = process_data(X, y)
    
    # 3. Train
    model, name = train_models(X_train_bal, y_train_bal, X_train_scaled, X_test, X_test_scaled, y_test)
    
    print("\n[DONE] Hoan tat! (Da luu bieu do phan tich & Model)")