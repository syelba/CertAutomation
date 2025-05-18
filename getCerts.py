import os
import sys
import requests
# Add the parent directory of cert_manager to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from datetime import datetime
from dotenv import load_dotenv
from loguru import logger
import subprocess
import logging
from pydantic import BaseModel
from auth import get_venafi_token
import config
import smtplib
import os
import urllib3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import paramiko
from scp import SCPClient
import pexpect
import time
from cert_manager.EditMongoDB import Mongo
from utils import run_command, send_email_with_error_log,get_ssl_expiry,getStatusCode,execute_command
import re
from netmiko import ConnectHandler
import vcert_commends


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
# Configure Loguru logging
log_filename = f"log_renew_{datetime.now().strftime('%H-%M_%d-%m-%Y')}.log"
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



def generate_CSR_Key(fqdn, city, state, Country, dst):
    try:
        logger.info(f"{dst} for generating CSR")
        cmd = vcert_commends.gen_csr(fqdn, city, state, Country, dst)
        logger.info(f"Command that was run: {cmd}")

        # Execute the command using run_command
        stdout, stderr, exit_status = run_command(cmd)

        if exit_status == 0:
            logger.info(f"CSR and key generated successfully for {fqdn}")
            return stdout.strip()
        else:
            logger.error(f"Error generating CSR for {fqdn}: {stderr.strip()}")
            return f"Error: {stderr.strip()}"
    except Exception as e:
        logger.error(f"Exception during CSR generation for {fqdn}: {e}")
        return f"Exception: {e}"


def renewCert(id, fqdn, type=None, pfxPassword=None, cmd=None):
    try:
        # Determine the command to run based on the type
        if type == "windows":
            command = vcert_commends.windows_crt_renew(cmd['token'], cmd['venafiURL'], fqdn, id, cmd['dst'], pfxPassword)
        elif type == "apache_nginx":
            command = vcert_commends.renew_apache_nginx(cmd['token'], cmd['venafiURL'], fqdn, id, cmd['dst'])
        elif type == "netapp":
            command = vcert_commends.renew_netapp(cmd['token'], cmd['venafiURL'], fqdn, id, cmd['dst'])
        else:
            logger.error(f"Unsupported certificate type: {type}")
            return f"Unsupported certificate type: {type}"
        logger.info(f"Command that was run: {command}")
        output, exit_status = run_command(command)
        if exit_status == 0:
            logger.info(f"{type} certs created for {fqdn}")
            return output.strip()
        else:
            logger.error(f"{type} Error: Command failed with exit status {exit_status} for {fqdn}")
            return f"Error: Command failed with exit status {exit_status}"
    except Exception as e:
        logger.error(f"{type} Error: {e} for {fqdn}")
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

def generate_csr_from_netapp(fqdn):
    """
    Connects to a NetApp device, generates a CSR, extracts the CSR and private key, saves them to files,
    and returns the data as a dictionary.
    Args:
        fqdn (str): Fully qualified domain name for the certificate.
    Returns:
        dict: A dictionary with 'csr', 'key', 'csr_file', and 'key_file' or an 'error' key if failure occurs.
    """
    logging.info(f"Starting CSR generation for FQDN: {fqdn}")
    netapp_device = {
        'device_type': 'terminal_server',
        'ip': os.getenv('NETAPP_IP'),
        'username': os.getenv('NETAPP_USER'),
        'password': os.getenv('NETAPP_PASSWORD'),
    }
    try:
        from netmiko import ConnectHandler  # Only import here to prevent error in offline env
        logging.info("Attempting to connect to NetApp device.")
        net_connect = ConnectHandler(**netapp_device)
        logging.info("Connected successfully.")

        output = net_connect.send_command(
            f'security certificate generate-csr {fqdn} -algorithm RSA -hash-function SHA256 -size 4096 -organization Intel -unit "CCG"'
        )
        csr_match = re.search(r'(-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----)', output, re.DOTALL)
        key_match = re.search(r'(-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)', output, re.DOTALL)

        if csr_match and key_match:
            csr = csr_match.group(1)
            key = key_match.group(1)

            csr_filename = f"{dst}/{fqdn}/{fqdn}.csr"
            key_filename = f"{dst}/{fqdn}/{fqdn}.key"

            with open(csr_filename, "w") as csr_file:
                csr_file.write(csr + "\n")
                logging.info(f"CSR saved to file: {csr_filename}")

            with open(key_filename, "w") as key_file:
                key_file.write(key + "\n")
                logging.info(f"Private key saved to file: {key_filename}")

            logging.info("CSR generation completed successfully.")
            return {
                "csr": csr,
                "key": key,
                "csr_file": csr_filename,
                "key_file": key_filename
            }

        else:
            logging.error("Failed to parse CSR or private key from device output.")
            return {"error": "Failed to parse CSR or private key."}

    except Exception as e:
        logging.exception("An error occurred during CSR generation.")
        return {"error": str(e)}

    finally:
        try:
            net_connect.disconnect()
            logging.info("Disconnected from NetApp device.")
        except:
            logging.warning("Failed to disconnect from NetApp device (possibly never connected).")

def renewCertNetapp(id, fqdn):
    cmd = f'sudo vcert renew -t {token} -u {venafiURL} --file {dst}/{fqdn}/{fqdn}.pem -id "{id}" --csr file:{dst}/{fqdn}/{fqdn}.csr'
    logger.info(f"Command that was run: {cmd}")
    try:
        process = os.popen(cmd)
        time.sleep(2)
        output = process.read()
        exit_status = process.close()
        if exit_status is None:
            logger.success(f"renewCertNetapp certs created for {fqdn}")
            return output.strip()
        else:
            logger.error(f"renewCertNetappx Error: Command failed with exit status {exit_status} for {fqdn}")
            return f"Error: Command failed with exit status {exit_status}"
    except Exception as e:
        logger.error(f"renewCertNetapp Error: {e} for {fqdn}")
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
                renewCert(pickup_id, fqdn,type= 'apache2')
            elif method == "nginx":
                renewCert(pickup_id, fqdn, type= 'nginx')
            elif method == "IIS":
                renewCert(pickup_id, fqdn, pfxPassword=server.get('pfxPassword', ''),type='windows')
            
            pickup(id=pickup_id, fqdn=fqdn)






if __name__ == '__main__':   
    get_cert_to_test()

