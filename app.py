import streamlit as st
import pandas as pd
import joblib
import re
import os
import socket
from urllib.parse import urlparse, urlunparse
import json
from datetime import datetime
import sklearn.tree

# ---  Fix for missing 'monotonic_cst' attribute in sklearn 1.6+ ---
if not hasattr(sklearn.tree.DecisionTreeClassifier, "monotonic_cst"):
    sklearn.tree.DecisionTreeClassifier.monotonic_cst = None

# --- Load trained model ---
model_path = "model/model.pkl"
model = load_model(model_path)

if model is None:
    st.error("❌ Model file not found. Make sure 'model/model.pkl' exists.")
    st.stop()

# Load or create metadata
metadata = load_model_metadata() or create_default_metadata()

# --- URL Validation and Sanitization ---
def validate_and_sanitize_url(url_input):
    """
    Validate and sanitize URL input.
    Returns: (is_valid, sanitized_url, error_message)
    """
    if not url_input or not url_input.strip():
        return False, None, "URL cannot be empty."
    
    # Strip whitespace
    url_input = url_input.strip()
    
    # Add protocol if missing
    if not url_input.startswith(('http://', 'https://')):
        url_input = 'https://' + url_input
    
    # Validate URL format
    try:
        parsed = urlparse(url_input)
        if not parsed.netloc:
            return False, None, "Invalid URL format. Please enter a valid URL."
        
        # Additional validation: netloc should contain at least a dot or be an IP
        netloc = parsed.netloc
        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        
        # Check if it's a valid domain (contains dot) or valid IP
        # Valid domains must have at least one dot (for TLD)
        # Exception: localhost (for development)
        ip_match = re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', netloc)
        is_valid_ip_addr = ip_match and all(0 <= int(octet) <= 255 for octet in ip_match.group(0).split('.'))
        is_localhost = netloc.lower() == 'localhost'
        has_tld = '.' in netloc
        
        if not (has_tld or is_valid_ip_addr or is_localhost):
            return False, None, "Invalid URL format. Please enter a valid URL with a domain name (e.g., example.com)."
        
        # Reconstruct URL to ensure it's properly formatted
        sanitized = urlunparse(parsed)
        return True, sanitized, None
    except Exception as e:
        return False, None, f"Invalid URL format: {str(e)}"

# --- Domain Extraction Utility ---
def extract_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""

# --- Typo-squatting Detection ---
def detect_typosquatting(domain):
    """
    Detect typo-squatting by checking similarity to well-known domains.
    Returns: (is_typosquatting, similarity_score, matched_domain)
    """
    if not domain:
        return False, 0.0, None
    
    # List of well-known domains to check against
    well_known_domains = [
        'google.com', 'gmail.com', 'googlemail.com',
        'facebook.com', 'fb.com',
        'amazon.com', 'aws.amazon.com',
        'microsoft.com', 'msn.com', 'outlook.com', 'hotmail.com',
        'apple.com', 'icloud.com',
        'paypal.com',
        'ebay.com',
        'twitter.com', 'x.com',
        'instagram.com',
        'linkedin.com',
        'github.com',
        'netflix.com',
        'youtube.com',
        'wikipedia.org',
        'reddit.com',
        'stackoverflow.com',
        'bankofamerica.com', 'chase.com', 'wellsfargo.com',
        'adobe.com',
        'dropbox.com',
    ]
    
    # Remove TLD for comparison
    domain_base = domain.split('.')[0] if '.' in domain else domain
    
    best_match = None
    best_score = 0.0
    
    for known_domain in well_known_domains:
        known_base = known_domain.split('.')[0]
        
        # Check for character substitutions (common typo-squatting)
        # Replace common lookalike characters
        domain_normalized = domain_base
        known_normalized = known_base
        
        # Common substitutions: 0->o, 1->l, 5->s, etc.
        substitutions = {
            '0': 'o', '1': 'l', '5': 's', '3': 'e',
            '4': 'a', '7': 't', '@': 'a', '$': 's'
        }
        
        for char, replacement in substitutions.items():
            domain_normalized = domain_normalized.replace(char, replacement)
            known_normalized = known_normalized.replace(char, replacement)
        
        # Calculate similarity
        # Only flag if there's a difference (not exact match)
        if domain_base == known_base:
            # Exact match - not typo-squatting
            continue
        
        if domain_normalized == known_normalized and domain_base != known_base:
            # Match after normalization but different original - high suspicion
            return True, 0.95, known_domain
        
        # Check Levenshtein distance (simple version)
        if len(domain_normalized) == len(known_normalized):
            differences = sum(1 for a, b in zip(domain_normalized, known_normalized) if a != b)
            similarity = 1.0 - (differences / len(domain_normalized))
            
            if similarity > best_score:
                best_score = similarity
                best_match = known_domain
        
        # Check if domain contains known domain (e.g., "go0gle" contains "google")
        # Only flag if the suspicious domain is similar length (typo-squatting, not subdomain)
        if known_normalized in domain_normalized:
            if len(domain_normalized) <= len(known_normalized) + 2:  # Allow 1-2 char difference
                return True, 0.90, known_domain
        elif domain_normalized in known_normalized:
            # Only flag if suspicious domain is close in length (not a subdomain)
            if len(domain_normalized) >= len(known_normalized) - 2:
                return True, 0.90, known_domain
    
    # Threshold for typo-squatting detection
    if best_score > 0.85:  # 85% similarity threshold
        return True, best_score, best_match
    
    return False, best_score, best_match

# --- Feature Extraction Function ---
def extract_features(url):
    """Extract features from URL for phishing detection."""
    features = {}
    features['Have_IP'] = 1 if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', url) else 0
    features['Have_At'] = 1 if '@' in url else 0
    
    # Feature 3: URL_Length
    features['URL_Length'] = len(url)
    features['URL_Depth'] = url.count('/')
    features['Redirection'] = 1 if url.count('//') > 1 else 0
    features['https_Domain'] = 1 if 'https' in url[8:] else 0
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|tinyurl|tr\.im|is\.gd|cli\.gs"
    features['TinyURL'] = 1 if re.search(shortening_services, url) else 0
    features['Prefix/Suffix'] = 1 if '-' in url else 0
    features['DNS_Record'] = 1
    features['Web_Traffic'] = 1
    features['Domain_Age'] = 12
    features['Domain_End'] = 6
    features['iFrame'] = 1 if "iframe" in url.lower() else 0
    features['Mouse_Over'] = 0
    
    # Feature 15: Right_Click - Always 0 (browser event, not extractable from URL)
    features['Right_Click'] = 0
    features['Web_Forwards'] = 1 if url.count('//') > 2 else 0
    return pd.DataFrame([features])

# --- Streamlit UI ---
url = st.text_input("Enter a URL:")

if st.button("Predict"):
    if url:
        input_features = extract_features(url)
        prediction = model.predict(input_features)[0]

        if prediction == 1:
            st.error(f"🔴 Phishing URL detected: {url}")
        else:
            st.success(f"🟢 Safe URL: {url}")

        # Optional: show extracted features
        # st.subheader("🔍 Extracted Features")
        # st.dataframe(input_features)
    else:
        st.warning("Please enter a URL to check.")

# --- Feedback Section ---
st.markdown("---")
st.subheader("💬 Share Your Feedback")
st.write("We'd love to hear from you! Tell us what you think about this Phishing URL Detector.")

st.markdown(
    "[👉 Click here to fill out the feedback form](https://docs.google.com/forms/d/e/1FAIpQLSeeW_J3U_xrOnBXnoQvSQFCoBw7o74LvffmJ1VW33leHEy5GQ/viewform?usp=publish-editor)",
    unsafe_allow_html=True
)
