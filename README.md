🔐 Phishing URL Detection using Machine Learning

A Machine Learning project focused on detecting phishing and malicious URLs using URL-based features, built and deployed as a web application.

📌 Why This Project?

Phishing attacks remain one of the most common cybersecurity threats. This project explores how machine learning can be applied to real-world security problems by analyzing URL structures to identify potentially malicious links.

The goal of this project was to:

Apply core machine learning concepts to a real dataset

Practice feature engineering

Train and evaluate a classification model

Deploy the model as an interactive web application

Learn best practices around model consistency and deployment

🧠 What the Model Does

The model classifies a given URL as either:

Safe

Phishing

It relies entirely on URL-based features, making it lightweight and fast, without needing to scrape website content.

🔍 Features Used

The model learns from structural and lexical properties of URLs, including:

Presence of IP addresses instead of domain names

Suspicious characters such as @ and -

URL length and depth

Redirection patterns

HTTPS usage and domain structure

Shortened URL detection

These features are dynamically computed at inference time to ensure consistency between training and deployment.

🛠️ Tech Stack & Skills Demonstrated

Python

scikit-learn (classification, model training, serialization)

Pandas & NumPy (data handling)

Feature engineering for ML

Model deployment with Streamlit

Git & GitHub (version control, open-source workflow)

🚀 Application Demo

The model is deployed using Streamlit, allowing users to test URLs in real time via a simple web interface.

Workflow:

User inputs a URL

Features are extracted and validated

The trained model predicts phishing vs safe

The result is displayed instantly

🧪 Model Training

Supervised classification approach

Trained on a labeled phishing dataset sourced online

Model saved using joblib and loaded during deployment

Feature consistency between training notebook and app ensured

Note: Some features currently act as placeholders due to unavailable external data (e.g. WHOIS). These are documented and planned for improvement.

📈 Learning Outcomes

Through this project, I gained hands-on experience with:

Translating raw data into ML-ready features

Understanding the impact of feature consistency on predictions

Debugging model behavior during deployment

Deploying ML models into usable applications

Handling real-world feedback and iterative improvement

⚠️ Current Limitations

WHOIS and certificate-based features are not yet implemented

No website content analysis (HTML, JavaScript)

Model decisions are limited to URL-level patterns

These limitations are intentional for a first version and serve as learning milestones.

🔮 Planned Improvements

Integrate WHOIS and domain age data

Add website content-based features

Character-level vectorization (n-grams)

Improve evaluation metrics and documentation

Add model explainability (feature importance)

[![Live Demo](https://qqehpwqjuyjdayhw3sqshb.streamlit.app/))

