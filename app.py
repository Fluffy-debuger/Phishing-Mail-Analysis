import streamlit as st
import os
import pickle
import base64
import email
from email.header import decode_header
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from eml_parser import check_urls_with_virustotal,parse_eml
import joblib
model = joblib.load('phishing_model.pkl')
vectorizer = joblib.load('tfidf_vectorizer.pkl')
emlpath="EMLFOLDER"

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def gmail_auth():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)


def fetch_and_save_eml_files(service, max_results=10):
    label_ids = ['INBOX']
    os.makedirs('EMLFOLDER', exist_ok=True)
    results = service.users().messages().list(userId='me', labelIds=label_ids, maxResults=max_results).execute()
    messages = results.get('messages', [])
    if not messages:
        print("No messages found.")
        return
    for msg in messages:
        try:
            msg_data = service.users().messages().get(userId='me', id=msg['id'], format='raw').execute()
            raw_data = msg_data['raw']
            decoded_email = base64.urlsafe_b64decode(raw_data.encode('UTF-8'))
            parsed_email = email.message_from_bytes(decoded_email)
            raw_subject = parsed_email.get("Subject", "no_subject")
            decoded_subject, encoding = decode_header(raw_subject)[0]
            if isinstance(decoded_subject, bytes):
                subject = decoded_subject.decode(encoding or "utf-8", errors="ignore")
            else:
                subject = decoded_subject
            subject = subject.strip().replace(" ", "_").replace("/", "_")[:50]

            if not subject:
                subject = "no_subject"

            filename = f"{subject}_{msg['id']}.eml"
            filepath = os.path.join("EMLFOLDER", filename)

            with open(filepath, 'wb') as f:
                f.write(decoded_email)

            print(f"Saved: {filename}")

        except Exception as e:
            print(f"Error saving message {msg['id']}: {e}")


st.header("Gmail Phishing Detector :")
col1,col2=st.columns(2)
with col1:
    x = st.number_input("Enter no. of emails to fetch:", min_value=1, step=1, format="%d")



print(x)

def connecttogmailandloadthemails():
    gmail_auth()
    s=gmail_auth()
    fetch_and_save_eml_files(s,int(x))
    #st.write("authenticated and loaded data")

def predict_phishing(combined_text):
    features = vectorizer.transform([combined_text])
    prediction = model.predict(features)
    return "Phishing" if prediction[0] == 1 else "Legitimate"

emlfiles=[i for i in os.listdir(emlpath)]
with col1:
    st.button(label="Connect with Gmail" ,on_click=connecttogmailandloadthemails)
selectmail=st.selectbox("select raw mail file",options=emlfiles)
print("you selected ", selectmail)
data=parse_eml(os.path.join(emlpath,selectmail))
text_combined=f"{data['subject']} {data['body_text']}"


def extractallurls(data):
    urls=data['urls']
    return urls


#print("URLS are :", extractallurls(data))

urllist=extractallurls(data)

feturescol1,classificationcol2,vtapiresco13=st.columns(3)

with feturescol1:
    st.header("Result :")
    st.write(f"Msg ID  : {data['message_id']}")
    st.write(f"Date    : {data['date']}")
    st.write(f"Sender  : {data['sender']}")
    st.write(f"Subject : {data['subject']}")
    st.write(f"SPF     : {data['spf']}")
    st.write(f"DMARC   : {data['dmarc']}")


with classificationcol2:
    st.header("Model Prdection :")
    if (predict_phishing(text_combined)=="Phishing"):
        st.warning(f" Mail-ID : {data['message_id']} is detected as {predict_phishing(text_combined)}")
    else :
        st.write(f" Mail-ID : {data['message_id']} is detected as {predict_phishing(text_combined)}")

with vtapiresco13:
    st.header("URL Scan Result :")
    st.write(check_urls_with_virustotal(urllist))
    


    
