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

# 🔧 Temporary fix for missing 'monotonic_cst' attribute in DecisionTreeClassifier
if not hasattr(sklearn.tree.DecisionTreeClassifier, "monotonic_cst"):
    sklearn.tree.DecisionTreeClassifier.monotonic_cst = None

# --- Model Metadata ---
MODEL_METADATA_PATH = "model/model_metadata.json"

def load_model_metadata():
    """Load model metadata if available."""
    if os.path.exists(MODEL_METADATA_PATH):
        try:
            with open(MODEL_METADATA_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    return None

def create_default_metadata():
    """Create default metadata structure."""
    return {
        "version": "1.0.0",
        "model_type": "DecisionTreeClassifier",
        "training_date": "Unknown",
        "accuracy": "Unknown",
        "features": [
            "Have_IP", "Have_At", "URL_Length", "URL_Depth", "Redirection",
            "https_Domain", "TinyURL", "Prefix/Suffix", "DNS_Record",
            "Web_Traffic", "Domain_Age", "Domain_End", "iFrame",
            "Mouse_Over", "Right_Click", "Web_Forwards"
        ],
        "description": "Phishing URL Detection Model"
    }

# --- Load trained model with caching ---
@st.cache_resource
def load_model(model_path):
    """Load and cache the model."""
    if os.path.exists(model_path):
        try:
            return joblib.load(model_path)
        except Exception as e:
            st.error(f"❌ Error loading model: {str(e)}")
            return None
    return None

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
def is_valid_ip(ip_string):
    """Validate if string is a valid IP address (0-255 for each octet)."""
    try:
        parts = ip_string.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False

def check_dns_record(domain):
    """Check if domain has valid DNS record."""
    try:
        socket.gethostbyname(domain)
        return 1
    except (socket.gaierror, socket.herror):
        return 0

def estimate_domain_age(domain):
    """
    Estimate domain age based on heuristics.
    Note: Actual domain age requires WHOIS lookup.
    Returns age in months (heuristic: newer domains more suspicious).
    """
    # Heuristic: shorter domains often older, longer/newer
    # This is a placeholder - real implementation would use WHOIS
    if len(domain) < 10:
        return 24  # Likely older
    elif len(domain) < 20:
        return 12  # Medium
    else:
        return 6  # Likely newer

def estimate_web_traffic(domain):
    """
    Estimate web traffic based on heuristics.
    Note: Actual traffic requires external API.
    Returns traffic score (heuristic).
    """
    # Heuristic: common TLDs and short domains likely have more traffic
    common_tlds = ['.com', '.org', '.net', '.edu', '.gov']
    has_common_tld = any(domain.endswith(tld) for tld in common_tlds)
    
    if has_common_tld and len(domain) < 15:
        return 1  # Likely high traffic
    else:
        return 0  # Likely low traffic

def extract_features(url):
    """Extract features from URL for phishing detection."""
    features = {}
    
    # Parse URL
    parsed = urlparse(url)
    domain = parsed.netloc.lower() if parsed.netloc else ""
    path = parsed.path
    
    # Feature 1: Have_IP - Check if URL contains valid IP address
    ip_match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', url)
    if ip_match:
        features['Have_IP'] = 1 if is_valid_ip(ip_match.group(1)) else 0
    else:
        features['Have_IP'] = 0
    
    # Feature 2: Have_At - Check for @ symbol
    features['Have_At'] = 1 if '@' in url else 0
    
    # Feature 3: URL_Length
    features['URL_Length'] = len(url)
    
    # Feature 4: URL_Depth - Count path segments (not including protocol slashes)
    if path:
        # Remove leading slash and count remaining segments
        path_segments = [seg for seg in path.split('/') if seg]
        features['URL_Depth'] = len(path_segments)
    else:
        features['URL_Depth'] = 0
    
    # Feature 5: Redirection - Check for // after protocol
    # Protocol has one //, so check if there are more
    protocol_end = url.find('://')
    if protocol_end != -1:
        after_protocol = url[protocol_end + 3:]
        features['Redirection'] = 1 if '//' in after_protocol else 0
    else:
        features['Redirection'] = 0
    
    # Feature 6: https_Domain - Check if protocol is HTTPS
    features['https_Domain'] = 1 if parsed.scheme.lower() == 'https' else 0
    
    # Feature 7: TinyURL - Check for URL shortening services (case-insensitive)
    shortening_services = r"(?i)(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|tinyurl|tr\.im|is\.gd|cli\.gs|t\.co|rebrand\.ly|short\.link|tiny\.cc|buff\.ly|adf\.ly|bit\.do|ow\.ly|q\.gs|v\.gd|is\.gd|bc\.vc|po\.st|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|scrnch\.me|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net)"
    features['TinyURL'] = 1 if re.search(shortening_services, url) else 0
    
    # Feature 8: Prefix/Suffix - Check if hyphen is in domain name (not path)
    if domain:
        features['Prefix/Suffix'] = 1 if '-' in domain else 0
    else:
        features['Prefix/Suffix'] = 0
    
    # Feature 9: DNS_Record - Check if domain resolves
    if domain:
        features['DNS_Record'] = check_dns_record(domain)
    else:
        features['DNS_Record'] = 0
    
    # Feature 10: Web_Traffic - Estimate based on heuristics
    if domain:
        features['Web_Traffic'] = estimate_web_traffic(domain)
    else:
        features['Web_Traffic'] = 0
    
    # Feature 11: Domain_Age - Estimate based on heuristics
    if domain:
        features['Domain_Age'] = estimate_domain_age(domain)
    else:
        features['Domain_Age'] = 0
    
    # Feature 12: Domain_End - TLD length
    if domain:
        # Extract TLD (last part after last dot)
        parts = domain.split('.')
        if len(parts) > 1:
            tld = parts[-1]
            features['Domain_End'] = len(tld)
        else:
            features['Domain_End'] = 0
    else:
        features['Domain_End'] = 0
    
    # Feature 13: iFrame - Check if "iframe" appears in URL (though this is URL-based, not HTML)
    # Note: This is a limitation - iframes are HTML elements, not URL features
    # Keeping for model compatibility but noting it's not ideal
    features['iFrame'] = 1 if "iframe" in url.lower() else 0
    
    # Feature 14: Mouse_Over - Always 0 (browser event, not extractable from URL)
    features['Mouse_Over'] = 0
    
    # Feature 15: Right_Click - Always 0 (browser event, not extractable from URL)
    features['Right_Click'] = 0
    
    # Feature 16: Web_Forwards - Check for multiple redirects/forwards
    # Count occurrences of // after protocol
    if protocol_end != -1:
        after_protocol = url[protocol_end + 3:]
        # Count // occurrences (each represents a potential forward)
        forward_count = after_protocol.count('//')
        features['Web_Forwards'] = 1 if forward_count > 0 else 0
    else:
        features['Web_Forwards'] = 0
    
    # Ensure features are in correct order (matching model expectations)
    feature_order = [
        'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
        'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
        'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame',
        'Mouse_Over', 'Right_Click', 'Web_Forwards'
    ]
    
    # Create DataFrame with features in correct order
    ordered_features = {key: features[key] for key in feature_order}
    return pd.DataFrame([ordered_features])

# --- Streamlit UI ---
st.title("🔍 Phishing URL Detection App")
st.write("Enter a URL to check if it's **Safe** or **Phishing** using a trained machine learning model.")

# Model status notice
if metadata.get('version') == '2.0.0':
    with st.expander("✅ Model Information", expanded=False):
        st.success(f"""
        **Model Version:** {metadata.get('version', 'Unknown')} - Retrained
        
        This model has been retrained with dynamic feature extraction, ensuring accurate predictions.
        Features like DNS_Record, Web_Traffic, Domain_Age, and Domain_End are now computed in real-time.
        
        **Test Accuracy:** {metadata.get('accuracy', {}).get('test', 'Unknown')*100 if isinstance(metadata.get('accuracy'), dict) else 'Unknown'}%
        """)
else:
    with st.expander("⚠️ Important Notice", expanded=False):
        st.warning("""
        **Model Compatibility Notice:**
        
        This model was originally trained with hardcoded feature values. The application now computes 
        features dynamically (DNS lookups, domain analysis, etc.), which may result in different 
        predictions than expected.
        
        **Recommendation:** Retrain the model using `python train_model.py` for optimal accuracy.
        """)

# Display model metadata in sidebar
with st.sidebar:
    st.header("📊 Model Information")
    st.write(f"**Version:** {metadata.get('version', 'Unknown')}")
    st.write(f"**Model Type:** {metadata.get('model_type', 'Unknown')}")
    st.write(f"**Training Date:** {metadata.get('training_date', 'Unknown')}")
    st.write(f"**Accuracy:** {metadata.get('accuracy', 'Unknown')}")
    st.write(f"**Features:** {len(metadata.get('features', []))}")

url = st.text_input("Enter a URL:")

if st.button("Predict"):
    if url:
        # Validate and sanitize URL
        is_valid, sanitized_url, error_msg = validate_and_sanitize_url(url)
        
        if not is_valid:
            st.error(f"❌ {error_msg}")
        else:
            try:
                # Extract features
                input_features = extract_features(sanitized_url)
                
                # Make prediction
                prediction = model.predict(input_features)[0]
                
                # Check for typo-squatting
                domain = extract_domain(sanitized_url)
                is_typosquatting, similarity, matched_domain = detect_typosquatting(domain)
                
                # Display result
                if prediction == 1:
                    st.error(f"🔴 **Phishing URL detected:** {sanitized_url}")
                    st.info("💡 **Note:** This is a prediction based on URL features. Please verify manually, especially for well-known domains.")
                else:
                    if is_typosquatting:
                        st.warning(f"⚠️ **Potential Typo-Squatting Detected:** {sanitized_url}")
                        st.error(f"🔴 **This URL may be a phishing attempt!**")
                        st.info(f"💡 **Warning:** This domain ({domain}) is suspiciously similar to '{matched_domain}' (similarity: {similarity*100:.1f}%). This is a common phishing technique called 'typo-squatting'.")
                        st.info("**Recommendation:** Do NOT visit this URL. Use the official website instead.")
                    else:
                        st.success(f"🟢 **Safe URL:** {sanitized_url}")
                        st.info("💡 **Note:** This is a prediction. Always exercise caution when visiting unfamiliar URLs.")
                
                # Optional: show extracted features
                with st.expander("🔍 View Extracted Features"):
                    st.dataframe(input_features.T, use_container_width=True)
                    st.caption("Feature values used for prediction")
                    
            except KeyError as e:
                st.error(f"❌ Feature mismatch error: {str(e)}. Model expects different features.")
            except IndexError as e:
                st.error(f"❌ Prediction error: {str(e)}. Please check the model file.")
            except Exception as e:
                st.error(f"❌ An error occurred during prediction: {str(e)}")
                st.exception(e)
    else:
        st.warning("Please enter a URL to check.")

# --- 💬 Feedback Section ---
st.markdown("---")
st.subheader("💬 Share Your Feedback")
st.write("We'd love to hear from you! Tell us what you think about this Phishing URL Detector.")

# Embed your Google Form link
st.markdown(
    "[👉 Click here to fill out the feedback form](https://docs.google.com/forms/d/e/1FAIpQLSeeW_J3U_xrOnBXnoQvSQFCoBw7o74LvffmJ1VW33leHEy5GQ/viewform?usp=publish-editor)",
    unsafe_allow_html=True
)
