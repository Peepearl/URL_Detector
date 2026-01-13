🔍 Phishing URL Detection System

Machine Learning · Streamlit Deployment

Python · Scikit-learn · Streamlit · Security · ML

🎯 Overview

This project is a machine learning based phishing URL detection system designed to help users identify whether a URL is safe or potentially malicious.

The model analyzes multiple URL based security indicators commonly associated with phishing attacks and provides real time predictions through an interactive Streamlit web application.

This project demonstrates practical skills in feature engineering, classical ML modeling, model deployment, and security focused data analysis, making it suitable for AI, ML, and data-focused internship roles.

✨ Key Features
🔐 URL-Based Security Analysis

The model evaluates URLs using features such as:

Presence of IP addresses in URLs

Suspicious symbols like @ or excessive redirects

URL length and depth

Use of URL shortening services

Prefix/suffix manipulation in domains

HTTPS domain inconsistencies

These features are commonly observed in phishing and social-engineering attacks.

🤖 Machine Learning Model

Supervised learning using RandomForestClassifier

Trained on a publicly available phishing URL dataset

Binary classification:

0 → Safe

1 → Phishing

Model serialized using joblib for deployment

🌐 Interactive Web App (Streamlit)

User-friendly input field for URLs

Instant prediction feedback (Safe vs Phishing)

Deployed using Streamlit Community Cloud

Includes a user feedback form for qualitative evaluation

🔗 Live Demo:
👉 Add your Streamlit app link here

https://your-streamlit-app-link

📊 Feature Engineering

The system extracts structured features directly from raw URLs using Python utilities such as:

re (regular expressions)

urllib.parse

ipaddress (standard library for IP detection)

This avoids reliance on black-box APIs and keeps the pipeline transparent and reproducible.

🛠️ Tech Stack

Programming Language: Python 3

ML & Data: pandas, numpy, scikit-learn

Model Persistence: joblib

Web App: Streamlit

Version Control: Git & GitHub

🚀 Quick Start
1️⃣ Clone the Repository
git clone https://github.com/your-username/URL_Detector.git
cd URL_Detector

2️⃣ Install Dependencies
pip install -r requirements.txt

3️⃣ Run the App Locally
streamlit run app.py

🧠 How the Model Works (High Level)

A user inputs a URL

The system extracts security-related features from the URL

The trained ML model evaluates the feature vector

The app displays whether the URL is safe or phishing

This mirrors how real-world URL reputation systems work at a basic level.

📈 Model Evaluation

Model performance was evaluated during training using standard classification metrics (accuracy, precision, recall)

Misclassifications are expected due to:

Evolving phishing tactics

Use of HTTPS by malicious sites

Limited access to live WHOIS or certificate metadata

The project is structured to allow future improvements.

🔮 Planned Improvements

Add WHOIS-based domain age features

Integrate website content analysis (HTML text patterns)

Apply character-level vectorization to better detect obfuscated URLs

Improve dataset balance and retraining strategy

Add model metadata and versioning

🤝 Contributions

Pull requests and suggestions are welcome.
This project is actively improving as part of continuous learning in AI security and applied machine learning

🙌 Acknowledgments

Public phishing URL datasets used for training

Open source Python and Streamlit communities

Reviewers and contributors who provided feedback via GitHub PRs

fidently in interviews

Just tell me 💙
