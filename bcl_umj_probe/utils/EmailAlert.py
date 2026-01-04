import smtplib
import ssl
from email.message import EmailMessage
import os
import logging

class EmailAlert:
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.logger = logging.getLogger(__name__)

    def send_email(self, subject: str, body: str):
        sender_email = os.getenv("SMTP_SENDER")
        receiver_email = os.getenv("SMTP_RECEIVER")
        app_password = os.getenv("SMTP_SENDER_APP_PASSWORD") 

        subject = subject
        body = body
      
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = receiver_email

        # Define the Gmail SMTP server and secure port
        smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.environ.get("SMTP_PORT", 465))

        # Create a secure SSL context
        context = ssl.create_default_context()

        try:
            # Connect to the server and send the email
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
                server.login(sender_email, app_password)
                server.send_message(msg)
        except smtplib.SMTPException as e:
            self.logger.error(f"Error: Unable to send email. {e}")
