"""
Training script for Phishing URL Detection Model
Uses the new feature extraction logic to train a model
"""

import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import re
import socket
from urllib.parse import urlparse
import os
import warnings
warnings.filterwarnings('ignore')

# Feature extraction functions (same as in app.py)
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
    """Estimate domain age based on heuristics."""
    if len(domain) < 10:
        return 24  # Likely older
    elif len(domain) < 20:
        return 12  # Medium
    else:
        return 6  # Likely newer

def estimate_web_traffic(domain):
    """Estimate web traffic based on heuristics."""
    common_tlds = ['.com', '.org', '.net', '.edu', '.gov']
    has_common_tld = any(domain.endswith(tld) for tld in common_tlds)
    
    if has_common_tld and len(domain) < 15:
        return 1  # Likely high traffic
    else:
        return 0  # Likely low traffic

def extract_features(url):
    """Extract features from URL for phishing detection (same as app.py)."""
    features = {}
    
    # Parse URL
    parsed = urlparse(url)
    domain = parsed.netloc.lower() if parsed.netloc else ""
    path = parsed.path
    
    # Feature 1: Have_IP
    ip_match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', url)
    if ip_match:
        features['Have_IP'] = 1 if is_valid_ip(ip_match.group(1)) else 0
    else:
        features['Have_IP'] = 0
    
    # Feature 2: Have_At
    features['Have_At'] = 1 if '@' in url else 0
    
    # Feature 3: URL_Length
    features['URL_Length'] = len(url)
    
    # Feature 4: URL_Depth
    if path:
        path_segments = [seg for seg in path.split('/') if seg]
        features['URL_Depth'] = len(path_segments)
    else:
        features['URL_Depth'] = 0
    
    # Feature 5: Redirection
    protocol_end = url.find('://')
    if protocol_end != -1:
        after_protocol = url[protocol_end + 3:]
        features['Redirection'] = 1 if '//' in after_protocol else 0
    else:
        features['Redirection'] = 0
    
    # Feature 6: https_Domain
    features['https_Domain'] = 1 if parsed.scheme.lower() == 'https' else 0
    
    # Feature 7: TinyURL
    shortening_services = r"(?i)(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|tinyurl|tr\.im|is\.gd|cli\.gs|t\.co|rebrand\.ly|short\.link|tiny\.cc|buff\.ly|adf\.ly|bit\.do|ow\.ly|q\.gs|v\.gd|is\.gd|bc\.vc|po\.st|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|scrnch\.me|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net)"
    features['TinyURL'] = 1 if re.search(shortening_services, url) else 0
    
    # Feature 8: Prefix/Suffix
    if domain:
        features['Prefix/Suffix'] = 1 if '-' in domain else 0
    else:
        features['Prefix/Suffix'] = 0
    
    # Feature 9: DNS_Record
    if domain:
        features['DNS_Record'] = check_dns_record(domain)
    else:
        features['DNS_Record'] = 0
    
    # Feature 10: Web_Traffic
    if domain:
        features['Web_Traffic'] = estimate_web_traffic(domain)
    else:
        features['Web_Traffic'] = 0
    
    # Feature 11: Domain_Age
    if domain:
        features['Domain_Age'] = estimate_domain_age(domain)
    else:
        features['Domain_Age'] = 0
    
    # Feature 12: Domain_End
    if domain:
        parts = domain.split('.')
        if len(parts) > 1:
            tld = parts[-1]
            features['Domain_End'] = len(tld)
        else:
            features['Domain_End'] = 0
    else:
        features['Domain_End'] = 0
    
    # Feature 13: iFrame
    features['iFrame'] = 1 if "iframe" in url.lower() else 0
    
    # Feature 14: Mouse_Over
    features['Mouse_Over'] = 0
    
    # Feature 15: Right_Click
    features['Right_Click'] = 0
    
    # Feature 16: Web_Forwards
    if protocol_end != -1:
        after_protocol = url[protocol_end + 3:]
        forward_count = after_protocol.count('//')
        features['Web_Forwards'] = 1 if forward_count > 0 else 0
    else:
        features['Web_Forwards'] = 0
    
    # Ensure features are in correct order
    feature_order = [
        'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
        'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
        'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame',
        'Mouse_Over', 'Right_Click', 'Web_Forwards'
    ]
    
    ordered_features = {key: features[key] for key in feature_order}
    return ordered_features

def load_dataset(file_path):
    """Load dataset from CSV file.
    
    Expected format:
    - Column 'url' or 'URL' with URLs
    - Column 'label' or 'Label' or 'phishing' with 0 (safe) or 1 (phishing)
    """
    df = pd.read_csv(file_path)
    
    # Find URL column
    url_col = None
    for col in ['url', 'URL', 'urls', 'URLs']:
        if col in df.columns:
            url_col = col
            break
    
    if url_col is None:
        raise ValueError("Could not find URL column. Expected 'url' or 'URL'")
    
    # Find label column
    label_col = None
    for col in ['label', 'Label', 'phishing', 'Phishing', 'target', 'Target']:
        if col in df.columns:
            label_col = col
            break
    
    if label_col is None:
        raise ValueError("Could not find label column. Expected 'label', 'phishing', or 'target'")
    
    return df[url_col].values, df[label_col].values

def create_sample_dataset(output_path='data/sample_dataset.csv'):
    """Create a sample dataset for training if no dataset is available."""
    print("Creating sample dataset...")
    
    # Sample URLs - mix of safe and phishing
    safe_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        "https://www.wikipedia.org",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        "https://www.netflix.com",
        "https://www.youtube.com",
        "https://www.facebook.com",
        "https://www.twitter.com",
        "https://www.linkedin.com",
        "https://www.reddit.com",
        "https://www.instagram.com",
        "https://www.python.org",
        "https://www.docker.com",
        "https://www.kubernetes.io",
        "https://www.ubuntu.com",
        "https://www.mozilla.org",
        "https://www.apache.org",
    ]
    
    phishing_urls = [
        "http://192.168.1.100/login",
        "https://bit.ly/suspicious-link",
        "https://goo.gl/malicious",
        "http://suspicious-site.com/login",
        "https://fake-bank-login.com",
        "http://phishing-example.net/verify",
        "https://secure-update-required.com",
        "http://account-verification-urgent.com",
        "https://suspicious-domain.org/login.php",
        "http://fake-paypal-login.com",
        "https://account-suspended-verify.com",
        "http://urgent-action-required.net",
        "https://suspicious-redirect.com//evil.com",
        "http://fake-amazon-login.com",
        "https://verify-account-now.com",
        "http://suspicious-payment.com",
        "https://account-locked-verify.com",
        "http://fake-ebay-login.com",
        "https://urgent-security-alert.com",
        "http://suspicious-bank-site.com",
    ]
    
    # Create DataFrame
    all_urls = safe_urls + phishing_urls
    labels = [0] * len(safe_urls) + [1] * len(phishing_urls)
    
    df = pd.DataFrame({
        'url': all_urls,
        'label': labels
    })
    
    # Create data directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Save to CSV
    df.to_csv(output_path, index=False)
    print(f"Sample dataset created: {output_path}")
    print(f"  Safe URLs: {len(safe_urls)}")
    print(f"  Phishing URLs: {len(phishing_urls)}")
    print(f"  Total: {len(all_urls)}")
    
    return output_path

def train_model(dataset_path=None, model_type='random_forest', test_size=0.2, random_state=42):
    """Train the phishing URL detection model."""
    
    # Load or create dataset
    if dataset_path is None or not os.path.exists(dataset_path):
        print("No dataset provided. Creating sample dataset...")
        dataset_path = create_sample_dataset()
    
    print(f"\nLoading dataset from: {dataset_path}")
    urls, labels = load_dataset(dataset_path)
    
    print(f"Dataset loaded: {len(urls)} URLs")
    print(f"  Safe (0): {np.sum(labels == 0)}")
    print(f"  Phishing (1): {np.sum(labels == 1)}")
    
    # Extract features
    print("\nExtracting features...")
    features_list = []
    failed_urls = []
    
    for i, url in enumerate(urls):
        try:
            features = extract_features(url)
            features_list.append(features)
        except Exception as e:
            print(f"Warning: Failed to extract features from URL {i}: {url[:50]} - {str(e)}")
            failed_urls.append(i)
            continue
    
    # Remove failed URLs from labels
    if failed_urls:
        labels = np.delete(labels, failed_urls)
        print(f"Removed {len(failed_urls)} URLs that failed feature extraction")
    
    # Convert to DataFrame
    feature_order = [
        'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
        'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
        'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame',
        'Mouse_Over', 'Right_Click', 'Web_Forwards'
    ]
    
    X = pd.DataFrame(features_list, columns=feature_order)
    y = labels
    
    print(f"\nFeatures extracted: {X.shape}")
    print(f"Feature columns: {list(X.columns)}")
    
    # Split data
    print(f"\nSplitting data (test_size={test_size})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Test set: {X_test.shape[0]} samples")
    
    # Train model
    print(f"\nTraining {model_type} model...")
    if model_type == 'random_forest':
        model = RandomForestClassifier(n_estimators=100, random_state=random_state, n_jobs=-1)
    elif model_type == 'decision_tree':
        model = DecisionTreeClassifier(random_state=random_state)
    else:
        raise ValueError(f"Unknown model type: {model_type}")
    
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\nEvaluating model...")
    y_train_pred = model.predict(X_train)
    y_test_pred = model.predict(X_test)
    
    train_accuracy = accuracy_score(y_train, y_train_pred)
    test_accuracy = accuracy_score(y_test, y_test_pred)
    
    print(f"\nTraining Accuracy: {train_accuracy:.4f} ({train_accuracy*100:.2f}%)")
    print(f"Test Accuracy: {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_test_pred, target_names=['Safe', 'Phishing']))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_test_pred))
    
    # Save model
    model_dir = "model"
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "model.pkl")
    
    print(f"\nSaving model to: {model_path}")
    joblib.dump(model, model_path)
    
    # Update metadata
    metadata = {
        "version": "2.0.0",
        "model_type": model_type.title().replace('_', ' '),
        "training_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "accuracy": {
            "training": float(train_accuracy),
            "test": float(test_accuracy)
        },
        "features": feature_order,
        "description": "Phishing URL Detection Model - Retrained with new feature extraction",
        "dataset_size": len(X),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "notes": [
            "Model retrained with dynamic feature extraction",
            "DNS_Record, Web_Traffic, Domain_Age, and Domain_End are now computed",
            "Some features (Mouse_Over, Right_Click) are always 0 as they represent browser events",
            "Domain_Age and Web_Traffic use heuristics - actual values would require external APIs"
        ],
        "last_updated": datetime.now().strftime("%Y-%m-%d")
    }
    
    metadata_path = os.path.join(model_dir, "model_metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"Metadata saved to: {metadata_path}")
    print("\n✅ Model training completed successfully!")
    print(f"\nModel saved to: {model_path}")
    print(f"Test Accuracy: {test_accuracy*100:.2f}%")
    
    return model, test_accuracy

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Train Phishing URL Detection Model')
    parser.add_argument('--dataset', type=str, default=None,
                        help='Path to dataset CSV file (if not provided, will create sample dataset)')
    parser.add_argument('--model-type', type=str, default='random_forest',
                        choices=['random_forest', 'decision_tree'],
                        help='Type of model to train')
    parser.add_argument('--test-size', type=float, default=0.2,
                        help='Proportion of dataset to use for testing')
    
    args = parser.parse_args()
    
    train_model(
        dataset_path=args.dataset,
        model_type=args.model_type,
        test_size=args.test_size
    )


