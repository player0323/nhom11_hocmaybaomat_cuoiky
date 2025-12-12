final_dataset_raw.csv : bộ dữ liệu thô (149k begin + phishing)
features.py : logic đặc trưng
extract_feature_csv.py : trích xuất đặc trưng để huấn luyện
train_model_final.py: huấn luyện mô hình

model_logistic_regression.pkl 
model_random_forest.pkl
model_svm.pkl
scaler.pkl : chuẩn hóa đặc trưng

app_feature_extractor.py : logic trích xuất đặc trưng khi chạy ứng dụng
app.py : chạy ứng dụng
templates/index.html : giao diện
final_whitelist.cvs: 600k url 
