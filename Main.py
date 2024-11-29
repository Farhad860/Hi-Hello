import os
import pandas as pd
import base64
import time
import random
import pdfkit
import datetime
import subprocess
import dns.resolver
from email.mime.text import MIMEText
from colorama import Fore, Style, init
from googleapiclient.discovery import build
from email.mime.multipart import MIMEMultipart
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# Initialize colorama
init(autoreset=True)

# Updated SCOPES to include `gmail.modify` for inbox/spam detection
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.labels'
]
EMAIL_LIST_FILE = 'Email_List.csv'
SUBJECT_FILE = 'Email_Subjects.txt'
TEMPLATES_FOLDER = 'Templates/'
HISTORY_FILE = 'History.csv'
CREDENTIALS_FOLDER = 'Json_Credentials/'
TOKEN_FOLDER = 'Token_Storage/'
SENDER_NAMES_FILE = 'Sender_Names.txt'  # New file for sender names

# Ensure directories exist
os.makedirs(CREDENTIALS_FOLDER, exist_ok=True)
os.makedirs(TOKEN_FOLDER, exist_ok=True)
os.makedirs(TEMPLATES_FOLDER, exist_ok=True)


def rotate_dns():
    """Rotate DNS by resolving to a new DNS server."""
    try:
        resolver = dns.resolver.Resolver()
        # Add a list of DNS servers to rotate through
        dns_servers = [
            '8.8.8.8',  # Google Public DNS
            '1.1.1.1',  # Cloudflare DNS
            '9.9.9.9',  # Quad9 DNS
            '208.67.222.222',  # OpenDNS
            '208.67.220.220',
            '8.8.4.4',
            '76.76.2.0',
            '76.76.10.0',
            '185.228.168.9',
            '185.228.169.9',
            '76.76.19.19',
            '76.223.122.150',
            '45.90.28.190',
            '64.6.64.6',
            '95.85.95.85',
            '216.146.35.35',
            '103.86.96.100',
            '8.26.56.26',
            '199.85.127.10',
            '199.85.126.10',
            '94.140.15.15',
            '94.140.14.14',
            '8.20.247.20',
            '209.244.0.4',
            '209.244.0.3',
            '77.88.8.1',
            '37.235.1.177',
            '149.112.112.112'
        ]
        # Pick a random DNS server for rotation
        selected_dns = random.choice(dns_servers)
        resolver.nameservers = [selected_dns]
        print(f"DNS switched to: {selected_dns}")
    except Exception as e:
        print(f"Error rotating DNS: {e}")


def authenticate_gmail(credentials_file):
    """Authenticate to Gmail API using a specific credential file and return the service."""
    token_file = os.path.join(TOKEN_FOLDER, f'{os.path.basename(credentials_file)}_token.json')
    creds = None

    # Check for an existing token file
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)

    # If no valid credentials are available, prompt for login
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save the credentials to token file for future use
        with open(token_file, 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)


def load_email_list():
    """Load email addresses from a CSV file."""
    try:
        df = pd.read_csv(EMAIL_LIST_FILE, usecols=['Email'], on_bad_lines="skip")
        if 'Email' not in df.columns:
            raise ValueError("The email list file must have a column named 'Email'")
        return df['Email'].dropna().tolist()
    except Exception as e:
        print(f"Error loading email list: {e}")
        return []


def load_subjects():
    """Load email subjects from a TXT file."""
    with open(SUBJECT_FILE, 'r') as file:
        subjects = [line.strip() for line in file.readlines()]
    if not subjects:
        raise ValueError("The subject file must contain at least one subject.")
    return subjects


def load_templates():
    """Load all email templates from the specified folder."""
    templates = []
    for filename in sorted(os.listdir(TEMPLATES_FOLDER)):
        filepath = os.path.join(TEMPLATES_FOLDER, filename)
        if filename.endswith('.html') or filename.endswith('.txt'):
            with open(filepath, 'r', encoding='utf-8') as file:
                templates.append(file.read())
    if not templates:
        raise ValueError("No templates found in the templates folder.")
    return templates


def load_sender_names():
    """Load sender names from a TXT file."""
    try:
        with open(SENDER_NAMES_FILE, 'r') as file:
            names = [line.strip() for line in file.readlines()]
        if not names:
            raise ValueError("The sender names file must contain at least one name.")
        return names
    except Exception as e:
        print(f"Error loading sender names: {e}")
        return []


def load_sent_history():
    """Load sent email history from a CSV file, or return an empty list if none exists."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        df = pd.read_csv(HISTORY_FILE)
        return df['Email'].tolist() if 'Email' in df.columns else []
    except pd.errors.EmptyDataError:
        return []


def save_sent_email(email, subject, status, json_file, sender_name):
    """Save the sent email information, including the Gmail JSON file used, status, and sender name."""
    with open(HISTORY_FILE, 'a') as f:
        f.write(f"{email},{subject},{status},{json_file},{sender_name}\n")


def encode_content(content):
    """Helper function to encode content to base64."""
    return base64.urlsafe_b64encode(content.encode()).decode()


def decode_content(encoded_content):
    """Helper function to decode base64 content."""
    return base64.urlsafe_b64decode(encoded_content.encode()).decode()



def check_spam_with_spamassassin(email_content):
    """Check the spam score using SpamAssassin."""
    try:
        # Use SpamAssassin's 'spamassassin' command-line tool
        # Pass the email content to spamassassin
        process = subprocess.Popen(
            ['spamassassin', '--test'], 
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        # Pass the email content to stdin
        stdout, stderr = process.communicate(input=email_content.encode())
        
        # Parse the output from SpamAssassin
        spam_score = stdout.decode()
        
        # Check if the score is high enough to consider the email spam
        if 'X-Spam-Status: Yes' in spam_score:
            print(f"SpamAssassin marked the email as spam: {spam_score}")
            return True
        else:
            print(f"SpamAssassin did not mark the email as spam: {spam_score}")
            return False
    except Exception as e:
        print(f"Error running SpamAssassin: {e}")
        return False


def check_spam_folder(service):
    """Check the spam folder for messages and use SpamAssassin for spam checking."""
    try:
        # Get messages from the SPAM label
        spam_messages = service.users().messages().list(userId='me', labelIds=['SPAM'], maxResults=10).execute()
        
        if 'messages' not in spam_messages:
            print("No messages found in the Spam folder.")
            return []
        
        messages = spam_messages['messages']
        spam_details = []

        print(f"Found {len(messages)} message(s) in Spam folder:")
        for msg in messages:
            # Retrieve message details
            message = service.users().messages().get(userId='me', id=msg['id']).execute()
            headers = message.get('payload', {}).get('headers', [])
            
            # Extract relevant information from headers
            email_data = {
                "From": next((header['value'] for header in headers if header['name'] == 'From'), "Unknown"),
                "Subject": next((header['value'] for header in headers if header['name'] == 'Subject'), "No Subject"),
                "Snippet": message.get('snippet', ''),
                "Id": msg['id']
            }

            # Get the raw email content to pass to SpamAssassin
            raw_email = service.users().messages().get(userId='me', id=msg['id'], format='raw').execute()
            email_content = base64.urlsafe_b64decode(raw_email['raw'].encode()).decode()
            
            # Check if SpamAssassin marks it as spam
            is_spam = check_spam_with_spamassassin(email_content)
            
            if is_spam:
                print(f"SpamAssassin marked the email as spam: {email_data['Subject']}")
                email_data['SpamAssassin'] = 'Spam'
            else:
                email_data['SpamAssassin'] = 'Not Spam'

            spam_details.append(email_data)

            # Print the details
            print(f"From: {email_data['From']}")
            print(f"Subject: {email_data['Subject']}")
            print(f"Snippet: {email_data['Snippet']}")
            print("-" * 40)
        
        return spam_details
    except Exception as e:
        print(f"Error checking spam folder: {e}")
        return []


def log_spam_details(spam_details):
    """Log spam folder details to a CSV file."""
    spam_log_file = 'Spam_Log.csv'
    try:
        df = pd.DataFrame(spam_details)
        if os.path.exists(spam_log_file):
            df.to_csv(spam_log_file, mode='a', header=False, index=False)
        else:
            df.to_csv(spam_log_file, index=False)
        print(f"Spam folder details logged to {spam_log_file}.")
    except Exception as e:
        print(f"Error logging spam details: {e}")


def delete_spam_emails(service, spam_emails):
    """Delete all spam emails listed."""
    try:
        for email in spam_emails:
            message_id = email.get('id')  # Safely access 'id' using `.get()`
            if not message_id:
                print(f"Skipping email: Missing 'id' field. Details: {email}")
                continue

            try:
                # Attempt to delete the email
                service.users().messages().delete(userId='me', id=message_id).execute()
                print(f"Deleted spam email with ID: {message_id}")
            except Exception as e:
                print(f"Failed to delete spam email {message_id}: {e}")
    except Exception as e:
        print(f"Error while deleting spam emails: {e}")


def generate_order_number():
    """Generate a random 4-5 digit order number."""
    return str(random.randint(100000, 99999999))


# Define the path to your wkhtmltopdf executable
path_to_wkhtmltopdf = os.path.join(os.getcwd(), 'Tools', 'Tools.exe')  # For Windows
# For Linux/Mac, it would be something like:
# path_to_wkhtmltopdf = os.path.join(os.getcwd(), 'wkhtmltopdf', 'wkhtmltopdf')

# Configure pdfkit to use the local wkhtmltopdf executable
config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)

def html_to_pdf(html_content, pdf_filename):
    """Convert HTML content to a PDF file and save it in the pdf_invoices folder."""
    try:
        pdfkit.from_string(html_content, pdf_filename, configuration=config)
        print(f"PDF Saved: {pdf_filename}")
    except Exception as e:
        print(f"Error generating PDF: {e}")


def create_email_message(to, subject, body, sender_email, sender_name):
    """Create a MIMEText email message with a base64 encoded sender name, encoded body, and subject."""
    # Generate the order number
    order_number = generate_order_number()

    # Define unsubscribe link (you can modify this to suit your unsubscribe mechanism)
    unsubscribe_link = f"To unsubscribe, click here: https://example.com/unsubscribe/{to}"

    # Replace placeholders in the email body
    current_date = datetime.datetime.now().strftime('%B %d, %Y')  # e.g., 'November 08, 2024'
    try:
        with open('TFN_Number.txt', 'r') as file:
            tfn_number = file.read().strip()
        with open('Body_Text.txt', 'r') as file:
            body_text = file.read().strip()   
    except FileNotFoundError as e:
        print(f"Error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error while loading data: {e}")
        raise

    # Replace placeholders in the body text and HTML body
    body = (body.replace("##S_Email##", to)
                .replace("##R_Date##", current_date)
                .replace("##TFN_Number##", tfn_number)
                .replace("##Body_Text##", body_text)
                .replace("##Order_Number##", order_number)
                .replace("##Unsubscribe_Link##", unsubscribe_link))  # Insert unsubscribe link here

    # Replace ##2S_Email2## with the actual recipient's email
    body_text = body_text.replace("##2S_Email2##", to)

    # Convert body to PDF and save it
    pdf_filename = f"PDF_Invoices/{order_number}.pdf"
    html_to_pdf(body, pdf_filename)

    # Create MIME multipart email
    message = MIMEMultipart()
    message['to'] = to
    message['from'] = f"=?utf-8?B?{base64.urlsafe_b64encode(sender_name.encode()).decode()}?= <{sender_email}>"
    message['subject'] = f"=?utf-8?B?{base64.urlsafe_b64encode(subject.encode()).decode()}?="

    # Attach the email body as text (with content from Body_Text.txt)
    message.attach(MIMEText(body_text, 'plain'))

    # Attach the generated PDF as an attachment
    with open(pdf_filename, 'rb') as pdf_file:
        pdf_attachment = MIMEText(pdf_file.read(), 'base64', 'utf-8')
        pdf_attachment.add_header('Content-Disposition', 'attachment', filename=f"{order_number}.pdf")
        message.attach(pdf_attachment)

    # Encode the message for sending
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw}


def send_email(service, to, subject, body, json_file, sender_name):
    """Send an email using Gmail API and log the Gmail JSON used."""
    try:
        sender_email = service.users().getProfile(userId='me').execute().get('emailAddress')
        message = create_email_message(to, subject, body, sender_email, sender_name)
        service.users().messages().send(userId='me', body=message).execute()
        print(f"{Fore.GREEN}Email sent to{Style.RESET_ALL} {to}")
        
        # Record successful send with sender name included
        save_sent_email(to, subject, 'Sent', json_file, sender_name)
        return True
    except Exception as e:
        print(f"{Fore.RED}Failed to send email to {to}: {e}{Style.RESET_ALL}")
        save_sent_email(to, subject, 'Failed', json_file, sender_name)
        return False


def main():
    email_list = load_email_list()
    subjects = load_subjects()
    templates = load_templates()
    sent_history = load_sent_history()
    sender_names = load_sender_names()

    credentials_files = [os.path.join(CREDENTIALS_FOLDER, file) for file in os.listdir(CREDENTIALS_FOLDER) if file.endswith('.json')]

    if not credentials_files:
        print("No credentials found! Place JSON credential files in the 'credentials/' folder.")
        return

    # Authenticate with the first credentials file
    credentials_file = credentials_files[0]
    service = authenticate_gmail(credentials_file)

    # Check the spam folder before sending emails
    print("Checking Spam folder before sending emails...")
    spam_emails = check_spam_folder(service)
    if spam_emails:
        # Optionally log spam details to CSV
        log_spam_details(spam_emails)

        # Prompt user to delete spam emails
        delete_prompt = input("Do you want to delete all spam emails? (y/n): ").strip().lower()
        if delete_prompt == 'y':
            delete_spam_emails(service, spam_emails)

    # Proceed with email sending logic...
    send_limit = int(input("Enter the number of emails to send (0 for unlimited): "))
    count = 0
    subject_index = 0
    credentials_index = 0
    template_index = 0
    sender_name_index = 0  # New index for sender names

    for email in email_list:
        if send_limit > 0 and count >= send_limit:
            print("Reached the send limit.")
            break

        # Rotate DNS before sending each email
        rotate_dns()

        credentials_file = credentials_files[credentials_index]
        service = authenticate_gmail(credentials_file)

        subject = subjects[subject_index]
        template = templates[template_index]
        sender_name = sender_names[sender_name_index]  # Get current sender name

        success = send_email(service, email, subject, template, credentials_file, sender_name)

        if success:
            count += 1

        # Rotate through subjects, credentials, templates, and sender names
        subject_index = (subject_index + 1) % len(subjects)
        credentials_index = (credentials_index + 1) % len(credentials_files)
        template_index = (template_index + 1) % len(templates)
        sender_name_index = (sender_name_index + 1) % len(sender_names)

        time.sleep(random.randint(5, 15))  # Sleep between sending emails

    print("All Emails Sent.")


if __name__ == '__main__':
    main()
