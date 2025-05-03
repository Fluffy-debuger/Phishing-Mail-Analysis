# Gmail Phishing Detector
This project is a **Streamlit-based web application** that integrates with **Gmail** to fetch and analyze emails for phishing detection. It uses **machine learning** for classification and integrates with **VirusTotal API** to analyze URLs present in emails.
---
## Features

- Authenticate and connect to your Gmail account.
- Fetch and save `.eml` email files from your inbox.
- Parse `.eml` files to extract headers, body, and URLs.
- Classify emails as **Phishing** or **Legitimate** using a trained ML model.
- Scan extracted URLs using the **VirusTotal** API.

### 1. Clone the Repository

```bash
git clone https://github.com/Fluffy-debuger/Phishing-Mail-Analysis.git
cd Phishing-Mail-Analysis-main
```

### 2. Create Virtual Environment & Install Dependencies

```bash
python -m venv .myenv
source .myenv/bin/activate  # On Windows use `.myenv\Scripts\activate`
pip install -r requirement.txt
```

### 3. Add Required Files

- Place your `credentials.json` file in the root directory (from Google Cloud Console).
- Add your `.env` file with any necessary environment variables (e.g., VirusTotal API key).

### 4. Run the App

```bash
streamlit run app.py
```

