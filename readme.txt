https://github.com/player0323/nhom11_hocmaybaomat_cuoiky.git


(1) final_dataset_raw.csv : bộ dữ liệu thô (149k begin + phishing)
(2) features.py : logic đặc trưng
(3) FINAL_DATASET_MERGED_COMPLETE.csv: 70k begin+phishing (trích xuất domain age + ssl age)
(4) extract_feature_csv.py : chạy file (2) trích xuất đặc trưng từ file (3) => file 5
(5) TRAINING_DATASET_FINAL.csv : dữ liệu đã trích xuất đặc trưng
(6) train_model_final.py: huấn luyện mô hình (dữ liệu file 5)


(7)
model_logistic_regression.pkl 
model_random_forest.pkl
model_svm.pkl
scaler.pkl : chuẩn hóa đặc trưng

(8)
app.py : chạy ứng dụng
app_feature_extractor.py : logic trích xuất đặc trưng khi chạy ứng dụng
templates/index.html : giao diện
final_whitelist.cvs: 600k url 
