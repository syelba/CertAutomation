from datetime import datetime
from loguru import logger
import config
import smtplib
import subprocess
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import time
import asyncssh
import asyncio
import getpass
import requests
import vcert_commends
from dotenv import load_dotenv
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


load_dotenv()

def run_command(cmd):
    logger.info(f"Command that was run: {cmd}")
    try:
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        stdout, stderr = process.communicate(input="\n\n")
        return_code = process.returncode

        if return_code == 0:
            logger.info("Command was successful")
        else:
            logger.error(f"Error: {stderr.strip()}")

        return stdout.strip(), stderr.strip(), return_code

    except Exception as e:
        logger.error(f"Exception: {e}")
        return None, f"Exception: {e}", -1


async def execute_command(hostname, username, password,command):
    async with asyncssh.connect(hostname, username = username,password=password,known_hosts=None) as conn:
        result = await conn.run(command)
        return result.stdout, result.stderr, result.exit_status


async def scp_upload(hostname, username, password, local_path, remote_path):
    async with asyncssh.connect(hostname, username=username, password=password, known_hosts=None) as conn:
        await asyncssh.scp(local_path, (conn, remote_path))
        print(f"Uploaded {local_path} to {hostname}:{remote_path}")


def send_email_with_error_log(recipient_emails_str, subject, body, file_path, 
                              smtp_server=None, smtp_port=587, sender_email=None, sender_password=None):
    try:
        # Use environment variables if parameters are not provided
        smtp_server = smtp_server or os.getenv('officeServer')
        sender_email = sender_email or os.getenv('Email')
        sender_password = sender_password or os.getenv('SysPassword')

        if not smtp_server or not sender_email or not sender_password:
            raise ValueError("SMTP server, sender email, and sender password must be provided.")

        # Convert comma-separated emails to a list
        recipient_emails = recipient_emails_str.split(",")

        # Create the email message
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = recipient_emails_str  # Keep the original string so all recipients receive the same email
        msg["Subject"] = subject

        # Attach email body
        msg.attach(MIMEText(body, "plain"))

        # Attach error log file (if exists)
        if file_path and os.path.exists(file_path):
            with open(file_path, "rb") as file:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(file.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(file_path)}")
                msg.attach(part)

        # Connect to SMTP server and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)  # Authenticate
        server.sendmail(sender_email, recipient_emails, msg.as_string())  # Send one email to all recipients
        server.quit()

        print("✅ Email sent successfully to:", recipient_emails_str)

    except Exception as e:
        print(f"❌ Failed to send email: {e}")



def getStatusCode(dns):
    PROXIS = {'http': '', 'https': ''}
    request = requests.get(url=dns, verify=False, proxies=PROXIS)
    return request.status_code

def get_current_time_with_date():
    now = datetime.now()
    return now.strftime("%H:%M_%d-%m-%Y")


def get_ssl_expiry(domain, port=443):
    cmd = f"""
    data=$(echo | openssl s_client -servername {domain} -connect {domain}:{port} 2>/dev/null | openssl x509 -noout -enddate | sed -e 's#notAfter=##')
    ssldate=$(date -d \"${{data}}\" '+%s')
    nowdate=$(date '+%s')
    diff=$((ssldate - nowdate))
    echo $((diff / 86400))
    """
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        if result.returncode == 0:
            logger.info(f"Days left for cert expiration for {domain}: {result.stdout.strip()}")
            return int(result.stdout.strip())
        else:
            logger.error(f"Error checking cert expiration for {domain}: {result.stderr.strip()}")
            return -1
    except Exception as e:
        logger.error(f"Exception checking cert expiration for {domain}: {e}")
        return -1


