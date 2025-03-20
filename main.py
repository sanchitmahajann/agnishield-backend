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

# Define input schema using Pydantic for validation
class URLRequest(BaseModel):
    url: str

# Feature extraction logic (replicated from Jupyter Notebook)
def extract_features(url: str):
    try:
        features = {}
        features['URL length'] = len(url)
        features['Number of dots'] = url.count('.')
        features['Number of slashes'] = url.count('/')
        features['Percentage of numerical characters'] = sum(c.isdigit() for c in url) / len(url)
        features['Dangerous characters'] = int(any(c in url for c in ['@', ';', '%', '&', '=', '+']))
        tld = tldextract.extract(url).suffix
        dangerous_tlds = {'cm', 'date', 'xyz'}
        features['Dangerous TLD'] = int(tld in dangerous_tlds)
        
        def calculate_entropy(s):
            probabilities = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
            return -sum([p * np.log2(p) for p in probabilities])
        
        features['Entropy'] = calculate_entropy(url)
        
        features['IP Address'] = int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}', urlparse(url).netloc)))
        
        features['Domain name length'] = len(tldextract.extract(url).domain)
        
        features['Suspicious keywords'] = int(any(keyword in url.lower() for keyword in ['login', 'verify', 'secure', 'account']))
        
        features['Repetitions'] = int(any(url.count(c * 4) > 0 for c in set(url)))
        
        features['Redirections'] = int(url.count('//') > 1)

        entropy_and_length_pca = pca.transform([[features['Entropy'], features['URL length']]])[0][0]
        
        return np.array([
            features['Number of dots'], 
            features['Number of slashes'], 
            features['Percentage of numerical characters'], 
            features['Dangerous characters'],
            features['Dangerous TLD'], 
            features['IP Address'], 
            features['Domain name length'], 
            features['Suspicious keywords'],
            features['Repetitions'], 
            features['Redirections'], 
            entropy_and_length_pca])

    except Exception as e:
        raise RuntimeError(f"Error during feature extraction: {str(e)}")

@app.post("/predict/")
async def predict(request: URLRequest):
    try:
        # Extract features from the input URL
        features = extract_features(request.url)
        
        print("Extracted Features:", features)  # Debugging log

        probability = model.predict_proba(features.reshape(1, -1))[0][1]
        
        print("Phishing Probability:", probability)  # Debugging log

        prediction = "phishing" if probability > 0.2 else "safe"
        
        return {"url": request.url, "prediction": prediction}

    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"ValueError during prediction: {str(e)}")
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=f"RuntimeError during prediction: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
