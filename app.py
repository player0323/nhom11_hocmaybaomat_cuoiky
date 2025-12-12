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
    # exit() hoac xu ly tuy y

models = {
    "LR": model_lr,
    "RF": model_rf,
    "SVM": model_svm
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
            scores = {}
            for name, model in models.items():
                # Pipeline da bao gom buoc Scaler ben trong, nen dua arr tho vao
                prob = model.predict_proba(arr)[0][1] 
                scores[name] = float(prob)

            # Tinh diem trung binh
            final_score = np.mean(list(scores.values()))

            # 3. Ket luan
            if final_score > 0.5:
                status = "DOC HAI (PHISHING)"
                css_class = "danger"
                confidence = final_score * 100
            else:
                status = "AN TOAN (BENIGN)"
                css_class = "success"
                confidence = (1 - final_score) * 100

            # 4. Thong tin chi tiet
            details = {
                "Tuoi Domain": features[27] if len(features) > 27 else "NA",
                "Tuoi SSL": features[28] if len(features) > 28 else "NA",
                "Whitelist": "Co" if extra_info.get("is_whitelisted") == 1 else "Khong",
                "Typosquatting": extra_info.get("typo_msg", "Khong")
            }

            result = {
                "status": status,
                "css_class": css_class,
                "confidence": f"{confidence:.2f}%",
                "scores": scores,
                "details": details
            }

        except Exception as e:
            error_msg = str(e)
            print(f"[LOI] {e}")
            traceback.print_exc()

    return render_template("index.html", url=url_input, result=result, error=error_msg)

if __name__ == "__main__":
    app.run(debug=True, port=5000)