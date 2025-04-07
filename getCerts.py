import os
from EditMongoDB import Mongo
from dotenv import load_dotenv
from loguru import logger
import subprocess
import logging
from pydantic import BaseModel
from auth import get_venafi_token
import config
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import paramiko
import paramiko
from scp import SCPClient
import pexpect
import time

def run_command(command_str, shell=False, timeout=10):
    """
    Executes a system command where arguments are comma-separated.

    :param command_str: A string with command arguments separated by commas (e.g., "ls,-l").
    :param shell: Whether to execute the command through the shell (default: False).
    :param timeout: Max time (in seconds) to wait for command completion.
    :return: A tuple (stdout, stderr, return_code)
    """
    # Split command by comma and remove extra spaces
    command_list = [arg.strip() for arg in command_str.split(",")]

    try:
        result = subprocess.run(
            command_list,
            shell=shell,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False  # Avoid auto-raising errors, handle them manually
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



load_dotenv()
DBname = os.getenv('DBname')
DBip = os.getenv('DBip')
venafiURL = os.getenv('venafiURL') 
SysAdminUser = os.getenv('SysAdminUser')
SysPassword = os.getenv('SysPassword') 
DBcollectionName = os.getenv("CollectionName")

#connect to DB class
readMongo = Mongo(DBname=DBname,ip=DBip,CollectionName=DBcollectionName)
servers = readMongo.Collection2List()
#check dns certificate days left
#days_left = get_ssl_expiry(domain="idcvm-zabbix.iil.intel.com")
#return number 0-90

# Configure logging
logging.basicConfig(filename="log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
#logging.warning(warning_msg)
#logging.error(error_msg)
#logging.info(f"vcert getcred output: {output}")


#get token from venafi:
token = get_venafi_token()

"""
pass
"""
def get_ssl_expiry(domain ,port=443):
    """check certificate experation date with DNS of the certificate with port 443 (using openssl commend not vcert/venfi tool)"""
    cmd = f"""
    data=$(echo | openssl s_client -servername {domain} -connect {domain}:{port} 2>/dev/null | openssl x509 -noout -enddate | sed -e 's#notAfter=##')
    ssldate=$(date -d "${{data}}" '+%s')
    nowdate=$(date '+%s')
    diff=$((ssldate - nowdate))
    echo $((diff / 86400))
    """
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)

        if result.returncode == 0:
            message = f"Days left for cert expiration for {domain}: {result.stdout.strip()}"
            logging.info(message)  # This already writes to log.txt
            return int(result.stdout.strip())  # Ensure returning an int
        
        else:
            message = f"Error checking certificate expiration for {domain}: {result.stderr.strip()}"
            logging.error(message)  # Log error (single line)
            return -1  # Return -1 on failure
        
    except Exception as e:
        message = f"Exception checking certificate expiration for {domain}: {e}"
        logging.error(message)  # Log exception (single line)
        return -1  # Return -1 on exception


"""
pass
"""
def generate_CSR_Key(fqdn, city, state, Country):
    """Generate a CSR and Key for each server using vcert."""    
    # Define the file paths
    dst = f"{os.getenv('dst')}"
    # Correct command formatting
    cmd = [
        "sudo", "vcert", "gencsr",
        "--cn", fqdn,
        "-o", "Intel",
        "--ou", "CCG",
        "-l", city,  # Locality (City)
        "--st", state,  # State
        "-c", Country,  # Country
        "--key-file", f"{dst}/{fqdn}/{fqdn}.key",
        "--csr-file", f"{dst}/{fqdn}/{fqdn}.csr"
    ]    
    try:
        # Start the command with pexpect to handle passphrase input
        child = pexpect.spawn(' '.join(cmd), encoding='utf-8')          
        # Handle the passphrase prompt and send an empty string
        child.expect('Enter key passphrase:')
        child.sendline('')  # Send an empty passphrase
        
        # Handle the verification passphrase prompt and send an empty string again
        child.expect('Verifying - Enter key passphrase:')
        child.sendline('')  # Send an empty passphrase          
        # Wait for the process to finish and capture the output
        child.expect(pexpect.EOF)
        output = child.before 
        exit_status = child.exitstatus       
        if exit_status == 0:
            message = f"CSR and key generated successfully for {fqdn}"
            logging.info(message)
            return output.strip()
        else:
            message = f"Error generating CSR for {fqdn}: {child.before}"
            logging.error(message)
            return f"Error: {child.before}"   
    except Exception as e:
        message = f"Exception during CSR generation for {fqdn}: {e}"
        logging.error(message)
        return f"Exception: {e}"



"""
pass
"""
def renewCertWin(id, fqdn, pfxPassword):
    """Renew existing certificate for Windows server using the os library"""
    # Construct the command as a single string
    cmd = f'sudo vcert renew -t {token} ' \
          f'-u {venafiURL} ' \
          f'--file {os.getenv("dst")}/{fqdn}/{fqdn}.pfx ' \
          f'--format pkcs12 --chain ignore --verbose ' \
          f'--id "{id}" ' \
          f'-csr service ' \
          f'--key-password {pfxPassword}'
    # Debugging: Print the command being executed
    print(f"Command that was run: {cmd}")
    try:
        # Run the command and capture its output using os.popen
        process = os.popen(cmd)  # Open a pipe to execute the command
        output = process.read()  # Capture the output (stdout)
        exit_status = process.close()  # Capture the exit status (None if successful)

        # Check the command's exit status
        if exit_status is None:
            logger.success(f"renewCertWin success for {fqdn}")
            return output.strip()
        else:
            logger.error(f"renewCertWin Error: Command failed with exit status {exit_status} for {fqdn}")
            return f"Error: Command failed with exit status {exit_status}"
    except Exception as e:
        logger.error(f"renewCertWin Error: {e} for {fqdn}")
        return f"Exception: {e}"


"""
pass
"""
def renewCertApach2(id, fqdn):
    """Renew cert for Zabbix server"""  
    # Construct the command as a single string
    cmd = f'sudo vcert renew -t "{token}" -u {venafiURL} --id "{id}" ' \
          f'--csr file:{os.getenv("dst")}/{fqdn}/{fqdn}.csr'
    # Debugging: Print the command being executed
    print(f"Command that was run: {cmd}") 
    try:
        # Run the command and capture its output using os.popen
        process = os.popen(cmd)  # Open a pipe to execute the command
        output = process.read()  # Capture the output (stdout)
        exit_status = process.close()  # Capture the exit status (None if successful)
        # Check the command's exit status
        if exit_status is None:
            logger.success(f"renewCertApach2 certs created for {fqdn}")
            return output.strip()
        else:
            logger.error(f"renewCertApach2 Error: Command failed with exit status {exit_status} for {fqdn}")
            return f"Error: Command failed with exit status {exit_status}"
    except Exception as e:
        logger.error(f"renewCertApach2 Error: {e} for {fqdn}")
        return f"Exception: {e}"

    
"""
pass
"""
def renewCertNginx(id, fqdn):
    """Renew cert for NGINX servers using the os library"""  
    # Command construction
    cmd = f'sudo vcert renew -t {token} -u {venafiURL} --id "{id}" ' \
          f'--csr file:{os.getenv("dst")}/{fqdn}/{fqdn}.csr'
    print(f"Command that was run: {cmd}")  # Debugging the exact command  
    try:
        # Run the command using os.popen
        process = os.popen(cmd)  # Open a pipe to the command
        time.sleep(2)  # Introduce the requested delay
        # Read the command's output
        output = process.read()  # Capture the command's stdout
        exit_status = process.close()  # Close the pipe and retrieve the exit status (None if successful)       
        # Check the command's exit status
        if exit_status is None:
            logger.success(f"renewCertNginx certs created for {fqdn}")
            return output.strip()
        else:
            logger.error(f"renewCertNginx Error: Command failed with exit status {exit_status} for {fqdn}")
            return f"Error: Command failed with exit status {exit_status}"
    except Exception as e:
        logger.error(f"renewCertNginx Error: {e} for {fqdn}")
        return f"Exception: {e}"


"""
pass
"""
def pickup(id, fqdn):
    cmd = f'sudo vcert pickup -u {venafiURL} -t {token} --pickup-id "{id}" ' \
          f'--cert-file /vol/store/PKI/automation/test/{fqdn}/{fqdn}.crt ' \
          f'--chain-file /vol/store/PKI/automation/test/{fqdn}/IntelSHA256RootCA.crt'
    # Debugging: print the command being executed
    print(f"Command that was run: {cmd}")
    try:
        # Run the command and capture its output using os.popen
        process = os.popen(cmd)  # Open a pipe to the command
        output = process.read()  # Read the output of the command
        exit_status = process.close()  # Close the pipe and capture the exit status (None if successful)  
        # Check the command's exit status
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
    for server in servers:
        if get_ssl_expiry(server['fqdn']) < config.days_remain:
            method = server['method']
            fqdn = server['fqdn']
            folder_path = f"{os.getenv('dst')}/{fqdn}"

            # Ensure the folder exists
            stdout, stderr, code = run_command(f"ls {os.getenv('dst')}")
            if not stdout or fqdn not in stdout.split():  # Fix: Handle NoneType case
                stdout, stderr, code = run_command(f"sudo mkdir -p {folder_path}")
                logging.info(f"Folder {folder_path} created.")

            # Step 1: Generate CSR Key
            generate_CSR_Key(
                fqdn=fqdn,
                city=server.get('local', ''),
                state=server.get('state', ''),
                Country=server.get('Country', '')
            )

            # Step 2: Renew Certificate based on method
            if method == "apache2":
                renewCertApach2(server['pickup-ID'], fqdn)
            elif method == "nginx":
                renewCertNginx(server['pickup-ID'], fqdn)
            elif method == "IIS":
                renewCertWin(server['pickup-ID'], fqdn, pfxPassword=server.get('pfxPassword', ''))

            # Step 3: Pickup certificate
            pickup(id=server['pickup-ID'], fqdn=fqdn)

                       

def transfer_files(remote_host, remote_user, remote_path, local_files, password=None, key_file=None):
    """
    Transfers three files to a remote server using SCP.
    :param remote_host: The remote server hostname or IP.
    :param remote_user: The remote username.
    :param remote_path: The destination path on the remote server.
    :param local_files: List of three local file paths to transfer.
    :param password: (Optional) Password for SSH authentication.
    :param key_file: (Optional) Path to the SSH private key file.
    """
    if len(local_files) != 3:
        raise ValueError("Exactly three files must be provided.")
    # Create an SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Connect using password or key
        if key_file:
            ssh.connect(remote_host, username=remote_user, key_filename=key_file)
        elif password:
            ssh.connect(remote_host, username=remote_user, password=password)
        else:
            raise ValueError("Either password or key_file must be provided.")
        # Create SCP client and transfer files
        with SCPClient(ssh.get_transport()) as scp:
            for file in local_files:
                scp.put(file, remote_path)
            print("Files transferred successfully!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ssh.close()



