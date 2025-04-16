import os
from cert_manager.EditMongoDB import Mongo
from dotenv import load_dotenv
from loguru import logger
import subprocess
from pydantic import BaseModel
from auth import get_venafi_token
import config
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import time
import requests
import urllib3
from datetime import datetime

# Configure Loguru logging
log_filename = f"log_{datetime.now().strftime('%H-%M_%d-%m-%Y')}.log"
logger.remove()
logger.add(log_filename, 
           level="DEBUG", 
           format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}", 
           rotation="10 MB", 
           compression="zip", 
           backtrace=True, 
           diagnose=True)
logger.add(lambda msg: print(msg, end=""), level="INFO")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def getStatusCode(dns):
    PROXIS = {'http': '', 'https': ''}
    request = requests.get(url=dns, verify=False, proxies=PROXIS)
    return request.status_code

def get_current_time_with_date():
    now = datetime.now()
    return now.strftime("%H:%M_%d-%m-%Y")

def run_command(command_str, shell=False, timeout=10):
    try:
        result = subprocess.run(
            command_str if shell else command_str.split(),
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return None, "Error: Command timed out", -1
    except FileNotFoundError:
        return None, "Error: Command not found", -2
    except Exception as e:
        return None, f"Error: {str(e)}", -3

def send_email_with_error_log(smtp_server, smtp_port, sender_email, sender_password, recipient_emails_str, subject, body, file_path):
    try:
        recipient_emails = recipient_emails_str.split(",")
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = recipient_emails_str
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        if file_path and os.path.exists(file_path):
            with open(file_path, "rb") as file:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(file.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(file_path)}")
                msg.attach(part)
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_emails, msg.as_string())
        server.quit()
        logger.success(f"Email sent successfully to: {recipient_emails_str}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")

load_dotenv()
dst = os.getenv('dst')
DBip = os.getenv('DBip')
venafiURL = os.getenv('venafiURL') 
SysAdminUser = os.getenv('SysAdminUser')
SysPassword = os.getenv('SysPassword') 
DBcollectionName = os.getenv("CollectionName")

readMongo = Mongo()
servers = readMongo.Collection2List()
token = get_venafi_token()

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

def generate_CSR_Key(fqdn, city, state, Country):
    logger.info(dst)
    cmd = f'sudo vcert gencsr --cn {fqdn} -o Intel --ou CCG -l {city} --st {state} -c {Country} --key-size 4096 --key-file {dst}/{fqdn}/{fqdn}.key --csr-file {dst}{fqdn}/{fqdn}.csr'
    logger.info(f"Command that was run: {cmd}")
    try:
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        stdout, stderr = process.communicate(input="\n\n")
        if process.returncode == 0:
            logger.success(f"CSR and key generated successfully for {fqdn}")
            return stdout.strip()
        else:
            logger.error(f"Error generating CSR for {fqdn}: {stderr.strip()}")
            return f"Error: {stderr.strip()}"
    except Exception as e:
        logger.error(f"Exception during CSR generation for {fqdn}: {e}")
        return f"Exception: {e}"

def renewCertWin(id, fqdn, pfxPassword):
    cmd = f'sudo vcert renew -t {token} -u {venafiURL} --file {dst}/{fqdn}/{fqdn}.pfx --format pkcs12 --chain ignore --verbose --id "{id}" -csr service --key-password {pfxPassword}'
    logger.info(f"Command that was run: {cmd}")
    try:
        process = os.popen(cmd)
        output = process.read()
        exit_status = process.close()
        if exit_status is None:
            logger.success(f"renewCertWin success for {fqdn}")
            return output.strip()
        else:
            logger.error(f"renewCertWin Error: Command failed with exit status {exit_status} for {fqdn}")
            return f"Error: Command failed with exit status {exit_status}"
    except Exception as e:
        logger.error(f"renewCertWin Error: {e} for {fqdn}")
        return f"Exception: {e}"

def renewCertApach2(id, fqdn):
    cmd = f'sudo vcert renew -t "{token}" -u {venafiURL} --id "{id}" --csr file:{dst}/{fqdn}/{fqdn}.csr'
    logger.info(f"Command that was run: {cmd}")
    try:
        process = os.popen(cmd)
        output = process.read()
        exit_status = process.close()
        if exit_status is None:
            logger.success(f"renewCertApach2 certs created for {fqdn}")
            return output.strip()
        else:
            logger.error(f"renewCertApach2 Error: Command failed with exit status {exit_status} for {fqdn}")
            return f"Error: Command failed with exit status {exit_status}"
    except Exception as e:
        logger.error(f"renewCertApach2 Error: {e} for {fqdn}")
        return f"Exception: {e}"

def renewCertNginx(id, fqdn):
    cmd = f'sudo vcert renew -t {token} -u {venafiURL} --id "{id}" --csr file:{dst}/{fqdn}/{fqdn}.csr'
    logger.info(f"Command that was run: {cmd}")
    try:
        process = os.popen(cmd)
        time.sleep(2)
        output = process.read()
        exit_status = process.close()
        if exit_status is None:
            logger.success(f"renewCertNginx certs created for {fqdn}")
            return output.strip()
        else:
            logger.error(f"renewCertNginx Error: Command failed with exit status {exit_status} for {fqdn}")
            return f"Error: Command failed with exit status {exit_status}"
    except Exception as e:
        logger.error(f"renewCertNginx Error: {e} for {fqdn}")
        return f"Exception: {e}"

def pickup(id, fqdn):
    cmd = f'sudo vcert pickup -u {venafiURL} -t {token} --pickup-id "{id}" --cert-file {dst}{fqdn}/{fqdn}.crt --chain-file {dst}{fqdn}/IntelSHA256RootCA.crt'
    logger.info(f"Command that was run: {cmd}")
    try:
        process = os.popen(cmd)
        output = process.read()
        exit_status = process.close()
        if exit_status is None:
            logger.success(f"pickup command succeeded for {fqdn}")
            return output.strip()
        else:
            logger.warning(f"pickup command failed with exit status {exit_status} for {fqdn}")
            return f"Error: Command failed with exit status {exit_status}"
    except Exception as e:
        logger.error(f"pickup Error: {e} for {fqdn}")
        return f"Exception: {e}"

def get_cert_to_test():
    if not dst:
        logger.error("Environment variable 'dst' is not set.")
        raise EnvironmentError("Environment variable 'dst' is not set.")

    for server in servers:
        if get_ssl_expiry(server.fqdn) < config.days_remain:
            fqdn = server.fqdn
            folder_path = os.path.join(dst, fqdn)
            logger.info(f"Checking folder: {folder_path}")
            pickup_id = server.pickup_ID
            method = server.method

            stdout, stderr, code = run_command(f"ls {dst}")
            if code != 0 or fqdn not in stdout.splitlines():
                stdout, stderr, code = run_command(f"sudo mkdir -p {folder_path}", shell=True)
                if code == 0:
                    logger.info(f"Folder {folder_path} created.")
                else:
                    logger.error(f"Failed to create folder {folder_path}: {stderr}")

            logger.info(f"Country for {fqdn}: {server.Country}")
            generate_CSR_Key(fqdn=fqdn, city=server.local, state=server.state, Country=server.Country)

            if method == "apache2":
                renewCertApach2(pickup_id, fqdn)
            elif method == "nginx":
                renewCertNginx(pickup_id, fqdn)
            elif method == "IIS":
                renewCertWin(pickup_id, fqdn, pfxPassword=server.get('pfxPassword', ''))

            pickup(id=pickup_id, fqdn=fqdn)




