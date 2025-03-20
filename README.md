---

# 🛡️ AGNISHIELD Backend

## 📄 Project Overview

This project aims to detect phishing URLs using machine learning and FastAPI. The system analyzes various features extracted from URLs to classify them as either "safe" or "phishing." It leverages an XGBoost model trained on a balanced dataset of legitimate and phishing URLs, with preprocessing and feature extraction steps implemented in Python.

---

## ✨ Key Features

- **Accurate Phishing Detection**: Utilizes machine learning algorithms to classify URLs as phishing or safe.
- **Feature Extraction**: Extracts 11 features from URLs, including entropy, dangerous characters, suspicious keywords, and PCA-transformed attributes.
- **FastAPI Backend**: Provides an API endpoint for real-time URL classification.
- **Scalable Deployment**: Easily deployable using Uvicorn and GitHub.

---

## 🛠️ Technologies Used

- **Backend Framework**: FastAPI
- **Machine Learning Model**: XGBoost
- **Libraries**:
  - pandas
  - numpy
  - scikit-learn
  - xgboost
  - tldextract
  - joblib
- **Deployment Tools**: Uvicorn, GitHub

---

## 📂 Project Structure

```
Phishing-Detection/
├── Phishing-Detection.ipynb    # Jupyter Notebook for training the model
├── main.py                     # FastAPI backend for URL classification
├── requirements.txt            # Dependencies for the project
├── phishing_model.joblib       # Saved machine learning model
├── pca_transformer.joblib      # Saved PCA transformer for feature extraction
├── scaler.joblib               # Saved scaler for preprocessing features
└── .gitignore                  # Ignore unnecessary files (e.g., __pycache__, .venv)
```

---

## 🚀 How to Run the Project Locally

### **1. Clone the Repository**
```bash
git clone https://github.com/sanchitmahajann/code-craft_backend.git
cd code-craft_backend
```

### **2. Set Up Virtual Environment**
Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate      # macOS/Linux
.venv\Scripts\activate         # Windows
```

### **3. Install Dependencies**
Install required libraries:
```bash
pip install -r requirements.txt
```

### **4. Run the FastAPI Server**
Start the backend server using Uvicorn:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Access the API documentation at:
```
http://127.0.0.1:8000/docs
```

---

## 📝 Feature Extraction Details

The following features are extracted from URLs for classification:

| Feature Name                | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| URL length                  | Length of the URL                                                          |
| Number of dots              | Count of dots (`.`) in the URL                                              |
| Number of slashes           | Count of slashes (`/`) in the URL                                           |
| Percentage of numerical characters | Ratio of numerical characters in the URL                                |
| Dangerous characters        | Presence of special characters (`@`, `;`, `%`, etc.)                       |
| Dangerous TLD               | Flag for dangerous top-level domains (`cm`, `date`, `xyz`)                 |
| Entropy                     | Measure of randomness in the URL                                            |
| IP Address                  | Flag if the URL contains an IP address                                      |
| Domain name length          | Length of the domain name                                                  |
| Suspicious keywords         | Presence of keywords like `login`, `verify`, `secure`, `account`           |
| Repetitions                 | Count of repeated characters (e.g., `aaaa`)                                |
| Redirections                | Count of redirections (`//`)                                               |
| Entropy and length (PCA)    | Combined feature derived using PCA transformation                          |

---

## 🎯 Expected Outcomes

- ✅ Accurate classification of phishing URLs with an XGBoost model achieving ~87% accuracy.
- 📈 Scalable deployment using FastAPI backend.

---

## 🌐 API Endpoints

### **POST /predict/**
Classifies a given URL as "safe" or "phishing."

#### Request Format:
```json
{
  "url": "http://example.com/login?user=admin"
}
```

#### Response Format:
```json
{
  "url": "http://example.com/login?user=admin",
  "prediction": "phishing",
  "probability": 0.85,
  "features": [1, 3, 0.0526315789, 1, 1, 0, 12, 1, 0, 0, 57.0504071]
}
```

---

## 📊 Model Training Workflow

1. **Data Collection**:
   - Gathered phishing URLs from open-source platforms like PhishTank.
   - Collected legitimate URLs from public datasets.

2. **Feature Extraction**:
   - Extracted relevant features from URLs (e.g., entropy, dangerous characters).

3. **Model Training**:
   - Balanced dataset using SMOTE (Synthetic Minority Over-sampling Technique).
   - Trained multiple models and selected XGBoost based on performance metrics.

4. **Evaluation**:
   - Achieved ~87% accuracy on test data.

5. **Deployment**:
   - Saved trained model and preprocessing components (PCA transformer and scaler).
   - Integrated with FastAPI for real-time predictions.

---

## 🔧 Future Enhancements

- Develop a browser extension for real-time phishing detection.
- Add more advanced features like HTML content analysis.
- Implement a GUI or web interface for user-friendly interaction.

---

## 👥 Authors

This project was developed by [Sanchit Mahajan](https://github.com/sanchitmahajann), [Magi Sharma](https://github.com/magi8101) and [Jeswin Sunsi](https://github.com/jeswinsunsi). Contributions are welcome!

---
