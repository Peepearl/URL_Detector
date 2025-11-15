import streamlit as st
import pandas as pd
import joblib
import re
import os
import sklearn.tree

# ---  Fix for missing 'monotonic_cst' attribute in sklearn 1.6+ ---
if not hasattr(sklearn.tree.DecisionTreeClassifier, "monotonic_cst"):
    sklearn.tree.DecisionTreeClassifier.monotonic_cst = None

# --- Load Trained Model ---
model_path = "model/model.pkl"

if os.path.exists(model_path):
    model = joblib.load(model_path)
else:
    st.error("❌ Model file not found. Make sure 'model/model.pkl' exists.")
    st.stop()

# --- App Title ---
st.title("🔍 Phishing URL Detection App")
st.write("Enter a URL to check if it’s **Safe** or **Phishing** using a trained machine learning model.")

# ---  Feature Extraction Function (matches your training notebook) ---
def extract_features(url):
    features = {}

    features['Have_IP'] = 1 if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', url) else 0
    features['Have_At'] = 1 if '@' in url else 0
    features['URL_Length'] = len(url)
    features['URL_Depth'] = url.count('/')
    features['Redirection'] = 1 if '//' in url[7:] else 0  # ignores http(s)://

    features['https_Domain'] = (
        1 if "https" in url.split('/')[2] else 0
        if len(url.split('/')) > 2 else 0
    )

    features['TinyURL'] = 1 if re.search(r'bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co', url) else 0

    features['Prefix/Suffix'] = (
        1 if '-' in url.split('/')[2] else 0
        if len(url.split('/')) > 2 else 0
    )

    # Placeholders (used in your training data)
    features['DNS_Record'] = 1
    features['Web_Traffic'] = 0
    features['Domain_Age'] = 0
    features['Domain_End'] = 0
    features['iFrame'] = 0
    features['Mouse_Over'] = 0
    features['Right_Click'] = 0
    features['Web_Forwards'] = 0

    return pd.DataFrame([features])

# --- Streamlit Input Section ---
url = st.text_input("Enter a URL:")

if st.button("Predict"):
    if url:
        input_features = extract_features(url)

        # Check if feature columns match what the model expects
        if hasattr(model, "feature_names_in_"):
            model_features = list(model.feature_names_in_)
            input_cols = list(input_features.columns)
            if model_features != input_cols:
                st.warning("⚠️ Feature mismatch detected — model may not predict correctly.")
                st.text(f"Model expects: {model_features}")
                st.text(f"App provides: {input_cols}")

        # --- Make Prediction ---
        try:
            prediction = model.predict(input_features)[0]

            if prediction == 1:
                st.error(f"🔴 Phishing URL detected: {url}")
            else:
                st.success(f"🟢 Safe URL: {url}")

        except Exception as e:
            st.error(f"⚠️ Prediction failed: {e}")

    else:
        st.warning("Please enter a URL to check.")

# --- Feedback Section ---
st.markdown("---")
st.subheader("💬 Share Your Feedback")
st.write("We’d love to hear from you! Tell us what you think about this Phishing URL Detector.")

st.markdown(
    "[👉 Click here to fill out the feedback form](https://docs.google.com/forms/d/e/1FAIpQLSeeW_J3U_xrOnBXnoQvSQFCoBw7o74LvffmJ1VW33leHEy5GQ/viewform?usp=publish-editor)",
    unsafe_allow_html=True
)
