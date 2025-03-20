from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np
import re
import tldextract
from urllib.parse import urlparse

# Load the saved model and PCA transformer
try:
    model = joblib.load("phishing_model.joblib")
    pca = joblib.load("pca_transformer.joblib")
except FileNotFoundError as e:
    raise RuntimeError(f"Missing required files: {str(e)}")

# Initialize FastAPI app
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this list to restrict origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define input schema using Pydantic for validation
class URLRequest(BaseModel):
    url: str

# Whitelisted safe domains
SAFE_DOMAINS = ['netlify.app', 'github.com', 'google.com', 'example.com']

# Feature extraction logic (replicated from Jupyter Notebook)
def extract_features(url: str):
    try:
        url_length = len(url)
        num_dots = url.count('.')
        num_slashes = url.count('/')
        percent_numerical_chars = sum(c.isdigit() for c in url) / len(url)
        dangerous_chars = int(any(c in url for c in ['@', ';', '%', '&', '=', '+']))
        tld = tldextract.extract(url).suffix
        dangerous_tlds = {'cm', 'date', 'xyz'}
        dangerous_tld = int(tld in dangerous_tlds)

        def calculate_entropy(s):
            probabilities = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
            return -sum([p * np.log2(p) for p in probabilities])

        entropy = calculate_entropy(url)
        ip_address = int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}', urlparse(url).netloc)))
        domain_name_length = len(tldextract.extract(url).domain)
        suspicious_keywords = int(any(keyword in url.lower() for keyword in ['login', 'verify', 'secure', 'account']))
        repetitions = int(any(url.count(c * 4) > 0 for c in set(url)))
        redirections = int(url.count('//') > 1)

        entropy_and_length_pca = pca.transform([[entropy, url_length]])[0][0]

        return np.array([
            num_dots, num_slashes, percent_numerical_chars, dangerous_chars,
            dangerous_tld, ip_address, domain_name_length, suspicious_keywords,
            repetitions, redirections, entropy_and_length_pca])

    except Exception as e:
        raise RuntimeError(f"Error during feature extraction: {str(e)}")

@app.post("/predict/")
async def predict(request: URLRequest):
    try:
        # Check if the domain is whitelisted
        domain = tldextract.extract(request.url).registered_domain
        if domain in SAFE_DOMAINS:
            return {"url": request.url, "prediction": "safe", "reason": "Whitelisted domain"}

        # Extract features from the input URL
        features = extract_features(request.url)
        
        print("Extracted Features:", features)  # Debugging log

        # Predict phishing probability using the model
        probability = model.predict_proba(features.reshape(1, -1))[0][1]
        
        print("Phishing Probability:", probability)  # Debugging log

        # Adjust threshold for classification (set to 0.2 for higher sensitivity)
        prediction = "phishing" if probability > 0.2 else "safe"
        
        return {"url": request.url, "prediction": prediction, "probability": float(probability)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during prediction: {str(e)}")
