import streamlit as st
import google.generativeai as genai
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import os
import base64
from email.mime.text import MIMEText
import email  # Import the email library

# --- Google AI Configuration ---
genai.configure(api_key=st.secrets["GOOGLE_API_KEY"])

# --- Gmail API Configuration ---
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.compose']
CLIENT_SECRET = st.secrets["GMAIL_CLIENT_SECRET"]
TOKEN_JSON = st.secrets.get("GMAIL_TOKEN_JSON", None)

# --- Streamlit Page Setup ---
st.set_page_config(page_title="Escalytics Gmail Automation", page_icon="📧", layout="wide")
st.title("⚡ Escalytics Gmail Automation by EverTech")

# --- Gmail Authentication ---
def authenticate_gmail():
    creds = None
    if TOKEN_JSON:
        creds = Credentials.from_authorized_user_info(info=TOKEN_JSON, scopes=SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = Flow.from_client_config(
                client_config=CLIENT_SECRET, scopes=SCOPES,
                redirect_uri='https://escalayticsnew.streamlit.app/flowName=GeneralOAuthFlow')  # Or a suitable redirect URI
            authorization_url, state = flow.authorization_url(
                access_type='offline', include_granted_scopes='true')
            st.write(f"Please visit this URL to authorize: {authorization_url}")
            authorization_response = st.text_input("Enter the authorization code:")

            if authorization_response:
                try: # Wrap in a try/except to catch potential errors during token exchange
                    flow.fetch_token(authorization_response=authorization_response)
                    creds = flow.credentials
                    st.secrets["GMAIL_TOKEN_JSON"] = creds.to_json()
                    st.experimental_rerun()
                except Exception as e:
                    st.error(f"Error during authorization: {e}")
                    return None # Return None to indicate failure

    return creds

creds = authenticate_gmail()

if not creds:
    st.stop()

service = build('gmail', 'v1', credentials=creds)

# --- AI Response Function ---
@st.cache_data(ttl=3600)
def get_ai_response(prompt, email_content):
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")  # Or your preferred model
        response = model.generate_content(prompt + email_content)
        return response.text.strip()
    except Exception as e:
        return f"Error: {e}"

# --- Function to create and save a draft reply ---
def create_draft_reply(email_id, original_email_content, suggested_reply):
    try:
        message = MIMEText(suggested_reply)
        message.add_header('In-Reply-To', email_id)
        message.add_header('References', email_id)

        raw_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

        draft = {
            'message': raw_message
        }

        service.users().drafts().create(userId='me', body=draft).execute()
        st.success(f"Draft reply created for email with ID: {email_id}")

    except Exception as e:
        st.error(f"Error creating draft: {e}")

# --- Streamlit Email Processing ---
st.header("Process Emails and Generate Drafts")

if st.button("Process Emails"):
    try:
        results = service.users().messages().list(userId='me', q='is:inbox').execute()
        messages = results.get('messages', [])

        if not messages:
            st.info('No emails found in your inbox.')
        else:
            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                email_content = ""

                if 'payload' in msg and 'parts' in msg['payload']:
                    for part in msg['payload']['parts']:
                        if 'data' in part['body']:
                            try:  # Decode with error handling
                                email_content += base64.urlsafe_b64decode(part['body']['data']).decode()
                            except Exception as e:
                                st.error(f"Error decoding part: {e}")
                elif 'raw' in msg:
                    try:
                        msg_str = base64.urlsafe_b64decode(msg['raw'].encode('ASCII'))
                        mime_msg = email.message_from_bytes(msg_str)
                        if mime_msg.is_multipart():
                            for part in mime_msg.walk():
                                if part.get_content_type() == 'text/plain':
                                    email_content += part.get_payload(decode=True).decode()
                        else:
                            email_content = mime_msg.get_payload(decode=True).decode()
                    except Exception as e:
                        st.error(f"Error parsing raw email: {e}")

                if email_content:
                    prompt = "Generate a suggested reply for the following email:\n\n"
                    suggested_reply = get_ai_response(prompt, email_content)
                    create_draft_reply(message['id'], email_content, suggested_reply)
                else:
                    st.warning(f"Could not extract content from email with ID: {message['id']}")

    except Exception as e:
        st.error(f"An error occurred: {e}")
