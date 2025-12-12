# -*- coding: utf-8 -*-
from flask import Flask, request, render_template
import numpy as np
import joblib
import warnings
from app_feature_extractor import extract_features_for_prediction
import traceback

warnings.filterwarnings("ignore")
app = Flask(__name__)

# =================== LOAD MODELS =====================
print("[INIT] Dang tai cac model...")
try:
    model_lr = joblib.load("model_logistic_regression.pkl")
    model_rf = joblib.load("model_random_forest.pkl")
    model_svm = joblib.load("model_svm.pkl")
except Exception as e:
    print(f"[LOI NGHIEM TRONG] Khong the tai model: {e}")


models = {
    "Logistic Regression": model_lr,
    "Random Forest": model_rf,
    "Support Vector Machine": model_svm
}

# =================== MAIN ROUTE =======================
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error_msg = ""
    url_input = ""

    if request.method == "POST":
        url_input = request.form["url"]
        try:
            # 1. Trich xuat feature
            features, extra_info = extract_features_for_prediction(url_input)
            arr = np.array(features).reshape(1, -1) # Shape (1, 30)

            # 2. Du doan qua cac model
            scores = [] # Dung list de luu chi tiet tung model
            probs_for_avg = []

            for name, model in models.items():
                # Lay xac suat la DOC HAI (Class 1)
                prob_phishing = model.predict_proba(arr)[0][1]
                probs_for_avg.append(prob_phishing)
                
                # Xu ly % theo chieu thuan
                if prob_phishing > 0.5:
                    label = "Độc hại"
                    confidence = prob_phishing * 100
                    color = "text-danger"
                else:
                    label = "An toàn"
                    confidence = (1 - prob_phishing) * 100
                    color = "text-success"

                scores.append({
                    "name": name,
                    "prob": confidence,
                    "label": label,
                    "color": color
                })

            # Tinh diem trung binh (dua tren xac suat doc hai)
            final_score_phishing = np.mean(probs_for_avg)

            # 3. Ket luan tong the
            if final_score_phishing > 0.5:
                status = "ĐỘC HẠI (PHISHING)"
                css_class = "danger"
                confidence_total = final_score_phishing * 100
            else:
                status = "AN TOÀN (BENIGN)"
                css_class = "success"
                confidence_total = (1 - final_score_phishing) * 100

            # 4. Thong tin chi tiet
            details = {
                "Tuoi Domain": features[27] if len(features) > 27 else "NA",
                "Tuoi SSL": features[28] if len(features) > 28 else "NA",
                "Whitelist": "Có" if extra_info.get("is_whitelisted") == 1 else "Không",
                "Typosquatting": extra_info.get("typo_msg", "Không")
            }

            result = {
                "status": status,
                "css_class": css_class,
                "confidence": f"{confidence_total:.2f}%",
                "model_details": scores, # Gui danh sach chi tiet da xu ly
                "details": details
            }

        except Exception as e:
            error_msg = str(e)
            print(f"[LOI] {e}")
            traceback.print_exc()

    return render_template("index.html", url=url_input, result=result, error=error_msg)

if __name__ == "__main__":
    app.run(debug=True, port=5000)