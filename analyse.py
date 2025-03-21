import requests
from bs4 import BeautifulSoup
import re
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
import validators
import ssl
import socket
import whois
from datetime import datetime
import urllib.parse


nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)
nltk.download('wordnet', quiet=True)

class WebsiteScamDetector:
    def __init__(self):
        
        self.scam_indicators = [
            'limited time offer', 'act now', 'risk free', 'guarantee', 'free gift',
            'discount', 'no credit check', 'no hidden fees', 'winner', 'congratulations',
            'lottery', 'prize', 'urgent', 'exclusive deal', 'best price', 'cash back',
            'double your money', 'earn money fast', 'get rich', 'investment opportunity',
            'no risk', 'special promotion', 'secret', 'you have been selected',
            'free access', 'once in a lifetime', 'instant approval', 'miracle',
            'cure', 'weight loss', 'enlargement', 'cheap', 'free trial'
        ]
        
        
        self.url_red_flags = [
            'secure', 'login', 'banking', 'account', 'verify', 'update', 'confirm',
            'paypal', 'ebay', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'instagram', 'verification', 'wallet', 'crypto'
        ]
        
        self.lemmatizer = WordNetLemmatizer()
        
        
        self.model = self._get_model()
        
    def _get_model(self):
        return RandomForestClassifier(n_estimators=100, random_state=42)
    
    def _clean_text(self, text):
        """Clean and preprocess text for analysis."""
        text = text.lower()

        text = re.sub(r'<.*?>', '', text)

        text = re.sub(r'http\S+', '', text)

        text = re.sub(r'[^a-zA-Z\s]', '', text)
        tokens = word_tokenize(text)
        stop_words = set(stopwords.words('english'))
        tokens = [token for token in tokens if token not in stop_words]
        tokens = [self.lemmatizer.lemmatize(token) for token in tokens]
        
        return ' '.join(tokens)
    
    def _get_website_content(self, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else ""

            meta_desc = ""
            meta_tag = soup.find("meta", attrs={"name": "description"})
            if meta_tag and "content" in meta_tag.attrs:
                meta_desc = meta_tag["content"]
            for script in soup(["script", "style"]):
                script.extract()
            
            # Get text
            text = soup.get_text(separator=' ', strip=True)
            
            # Extract links
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            
            return {
                'title': title,
                'meta_description': meta_desc,
                'text': text,
                'links': links,
                'html': response.text
            }
            
        except Exception as e:
            print(f"Error fetching website content: {e}")
            return None
    
    def _analyze_url(self, url):
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'num_dots': domain.count('.'),
            'num_hyphens': domain.count('-'),
            'num_underscores': domain.count('_'),
            'num_digits': sum(c.isdigit() for c in domain),
            'has_https': 1 if parsed_url.scheme == 'https' else 0,
            'suspicious_words_in_url': 0
        }
        
        domain_parts = re.split(r'[.-]', domain.lower())
        path_parts = parsed_url.path.lower().split('/')
        all_parts = domain_parts + path_parts
        
        for word in all_parts:
            if word in self.url_red_flags:
                features['suspicious_words_in_url'] += 1
        
        return features
    
    def _check_ssl_cert(self, url):
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    not_after = cert['notAfter']
                    not_before = cert['notBefore']

                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    issue_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')

                    cert_age = (datetime.now() - issue_date).days
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    return {
                        'has_ssl': True,
                        'cert_issuer': issuer.get('organizationName', 'Unknown'),
                        'cert_age_days': cert_age,
                        'days_until_expiry': days_until_expiry,
                        'is_expired': days_until_expiry < 0
                    }
            
        except Exception as e:
            return {
                'has_ssl': False,
                'cert_issuer': None,
                'cert_age_days': None, 
                'days_until_expiry': None,
                'is_expired': None,
                'error': str(e)
            }
    
    def _check_domain_age(self, url):
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if creation_date:
                domain_age = (datetime.now() - creation_date).days
            else:
                domain_age = None
            
            return {
                'domain_age_days': domain_age,
                'registrar': w.registrar,
                'is_registered': True if w.domain_name else False
            }
            
        except Exception as e:
            return {
                'domain_age_days': None,
                'registrar': None,
                'is_registered': False,
                'error': str(e)
            }
    
    def _extract_text_features(self, content):
        """Extract NLP features from website content."""
        if not content:
            return {}
        
        # Clean text
        cleaned_text = self._clean_text(content['text'])
        cleaned_title = self._clean_text(content['title'])
        cleaned_meta = self._clean_text(content['meta_description'])
        
        # Combine all text
        all_text = cleaned_title + " " + cleaned_meta + " " + cleaned_text
        
        # Check for scam indicators
        scam_indicators_count = 0
        for indicator in self.scam_indicators:
            if indicator in all_text:
                scam_indicators_count += 1
        
        # Count number of external links
        external_links = 0
        internal_links = 0
        
        if content['links']:
            base_domain = urllib.parse.urlparse(content['links'][0]).netloc
            for link in content['links']:
                if link.startswith('http'):
                    link_domain = urllib.parse.urlparse(link).netloc
                    if link_domain != base_domain:
                        external_links += 1
                    else:
                        internal_links += 1
                else:
                    internal_links += 1
        
        # Calculate text statistics
        word_count = len(all_text.split())
        avg_word_length = np.mean([len(word) for word in all_text.split()]) if word_count > 0 else 0
        
        # Check for excessive punctuation (signs of urgency or excitement)
        exclamation_count = content['text'].count('!')
        question_count = content['text'].count('?')
        exclamation_ratio = exclamation_count / len(content['text']) if len(content['text']) > 0 else 0
        
        # Check for ALL CAPS text (shouting)
        caps_ratio = sum(1 for c in content['text'] if c.isupper()) / len(content['text']) if len(content['text']) > 0 else 0
        
        return {
            'scam_indicators_count': scam_indicators_count,
            'external_links': external_links,
            'internal_links': internal_links,
            'link_ratio': external_links / (internal_links + 1),  # Adding 1 to avoid division by zero
            'word_count': word_count,
            'avg_word_length': avg_word_length,
            'exclamation_count': exclamation_count,
            'exclamation_ratio': exclamation_ratio,
            'caps_ratio': caps_ratio,
            'text_length': len(content['text']),
            'has_contact_info': 1 if re.search(r'contact|about us|about me|phone|email', content['text'].lower()) else 0,
            'has_privacy_policy': 1 if re.search(r'privacy|policy|terms', content['text'].lower()) else 0,
            'has_form': 1 if re.search(r'<form|<input|type="text"|type="email"|type="password"', content['html'].lower()) else 0
        }
    
    def analyze_website(self, url):
        # Validate URL
        if not validators.url(url):
            return {
                'valid_url': False,
                'scam_probability': None,
                'analysis': None,
                'error': 'Invalid URL format'
            }

        content = self._get_website_content(url)
        if not content:
            return {
                'valid_url': True,
                'scam_probability': None,
                'analysis': None,
                'error': 'Failed to retrieve website content'
            }
        
        # Analyze URL
        url_features = self._analyze_url(url)
        ssl_features = self._check_ssl_cert(url)
        domain_features = self._check_domain_age(url)
        text_features = self._extract_text_features(content)
        all_features = {**url_features, **ssl_features, **domain_features, **text_features}
        red_flags = []
        if url_features['suspicious_words_in_url'] > 0:
            red_flags.append(f"URL contains {url_features['suspicious_words_in_url']} suspicious keywords")
        
        if url_features['num_hyphens'] > 2:
            red_flags.append("URL contains an unusual number of hyphens")
            
        # Check SSL
        if not ssl_features['has_ssl']:
            red_flags.append("Website does not use HTTPS (secure connection)")
        
        if ssl_features.get('is_expired'):
            red_flags.append("SSL certificate is expired")
            
        # Check domain age
        if domain_features['domain_age_days'] is not None and domain_features['domain_age_days'] < 90:
            red_flags.append(f"Domain is very new (only {domain_features['domain_age_days']} days old)")
          
        if text_features['scam_indicators_count'] > 3:
            red_flags.append(f"Content contains {text_features['scam_indicators_count']} scam indicator keywords")
            
        if text_features['exclamation_ratio'] > 0.01:
            red_flags.append("Excessive use of exclamation marks")
            
        if text_features['caps_ratio'] > 0.3:
            red_flags.append("Excessive use of ALL CAPS (shouting)")
            
        if text_features['has_contact_info'] == 0:
            red_flags.append("No contact information found")
            
        if text_features['has_privacy_policy'] == 0:
            red_flags.append("No privacy policy or terms of service found")
            
        if text_features['has_form'] == 1 and ssl_features['has_ssl'] == False:
            red_flags.append("Website contains forms but does not use HTTPS")

        scam_score = len(red_flags) / 10  
        scam_probability = min(scam_score, 1.0)
        
        return {
            'valid_url': True,
            'scam_probability': scam_probability,
            'risk_level': 'High' if scam_probability > 0.7 else 'Medium' if scam_probability > 0.4 else 'Low',
            'red_flags': red_flags,
            'all_features': all_features,
            'recommendation': 'Avoid this website' if scam_probability > 0.7 else 'Proceed with caution' if scam_probability > 0.4 else 'Likely legitimate'
        }

# Example usage
if __name__ == "__main__":
    detector = WebsiteScamDetector()
    
    test_url = input("Enter a website URL to analyze: ")
    
    result = detector.analyze_website(test_url)
    
    print("\n===== Website Scam Analysis =====")
    print(f"URL: {test_url}")
    
    if not result['valid_url']:
        print(f"Error: {result['error']}")
    elif 'error' in result and result['error']:
        print(f"Analysis failed: {result['error']}")
    else:
        print(f"Scam Probability: {result['scam_probability']:.2f}")
        print(f"Risk Level: {result['risk_level']}")
        print("\nRed Flags Detected:")
        if result['red_flags']:
            for flag in result['red_flags']:
                print(f"- {flag}")
        else:
            print("- None detected")
        
        print(f"\nRecommendation: {result['recommendation']}")
