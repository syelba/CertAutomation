from utils import run_command, send_email_with_error_log,get_ssl_expiry,getStatusCode,execute_command
import os 
from dotenv import load_dotenv
import time
from loguru import logger
from datetime import datetime
load_dotenv()
import vcert_commends


# Configure Loguru logging
log_filename = f"log_deploy_{datetime.now().strftime('%H-%M_%d-%m-%Y')}.log"
logger.remove()
logger.add(log_filename, 
           level="DEBUG", 
           format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}", 
           rotation="10 MB", 
           compression="zip", 
           backtrace=True, 
           diagnose=True)
logger.add(lambda msg: print(msg, end=""), level="INFO")



def deploy_cert(ip, host_user, host_password, crt, key, rootca, dns, fqdn, type):
    path = os.getenv('dst') + fqdn
    try:
        logger.info(f"Starting certificate deployment for {fqdn} on {ip}")

        # Copy certificate
        logger.info("Copying certificate...")
        stdout, stderr, code = run_command(f"sshpass -p '{host_password}' scp {path}/{fqdn}_test.crt {host_user}@{ip}:/home/{host_user}/")
        if code != 0:
            logger.error(f"Failed to copy certificate: {stderr}")
            raise Exception(f"Failed to copy certificate: {stderr}")

        # Copy key
        logger.info("Copying key...")
        stdout, stderr, code = run_command(f"sshpass -p '{host_password}' scp {path}/{fqdn}_test.key {host_user}@{ip}:/home/{host_user}/")
        if code != 0:
            logger.error(f"Failed to copy key: {stderr}")
            raise Exception(f"Failed to copy key: {stderr}")

        # Copy root CA
        logger.info("Copying root CA...")
        stdout, stderr, code = run_command(f"sshpass -p '{host_password}' scp {path}/IntelSHA256RootCA.crt {host_user}@{ip}:/home/{host_user}/")
        if code != 0:
            logger.error(f"Failed to copy root CA: {stderr}")
            raise Exception(f"Failed to copy root CA: {stderr}")
        
        

        if type == 'apache2':

            # edit config file key 
            logger.info("Creating fullchain certificate for apache2...")
            stdout, stderr, code = run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} sudo sed -i -e 's/certAutomation_test.key/certAutomation.key/g' /etc/nginx/sites-available/certapp")
            if code != 0:
                logger.error(f"Failed to edit config file key: {stderr}")
                raise Exception(f"Failed to edit config file key: {stderr}")
            
            # edit config file crt 
            logger.info("Creating fullchain certificate for apache2...")
            stdout, stderr, code = run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} sudo sed -i -e 's/certAutomation.key/certAutomation_test.key/g' /etc/nginx/sites-available/certapp")
            if code != 0:
                logger.error(f"Failed to edit config file crt: {stderr}")
                raise Exception(f"Failed to edit config file crt: {stderr}")

            # Restart Apache service
            logger.info("Restarting Apache service...")
            stdout, stderr, code = run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} 'sudo systemctl restart apache2.service'")
            if code != 0:
                logger.error(f"Failed to restart Apache service: {stderr}")
                raise Exception(f"Failed to restart Apache service: {stderr}")

        elif type == 'nginx':
            # Concatenate certificate and root CA for Nginx
            logger.info("Creating fullchain certificate for Nginx...")
            stdout, stderr, code = run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} cat {fqdn}_test.crt IntelSHA256RootCA.crt > fullchain_test.crt")
            if code != 0:
                logger.error(f"Failed to create fullchain certificate: {stderr}")
                raise Exception(f"Failed to create fullchain certificate: {stderr}")
            
            # edit config file key 
            logger.info("Creating fullchain certificate for Nginx...")
            stdout, stderr, code = run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} sudo sed -i -e 's/certAutomation_test.key/certAutomation.key/g' /etc/nginx/sites-available/certapp")
            if code != 0:
                logger.error(f"Failed to edit config file key: {stderr}")
                raise Exception(f"Failed to edit config file key: {stderr}")
            
            # edit config file crt 
            logger.info("Creating fullchain certificate for Nginx...")
            stdout, stderr, code = run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} sudo sed -i -e 's/certAutomation.key/certAutomation_test.key/g' /etc/nginx/sites-available/certapp")
            if code != 0:
                logger.error(f"Failed to edit config file crt: {stderr}")
                raise Exception(f"Failed to edit config file crt: {stderr}")

            # Restart Nginx service
            logger.info("Restarting Nginx service...")
            stdout, stderr, code = run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} 'sudo systemctl restart nginx.service'")
            if code != 0:
                logger.error(f"Failed to restart Nginx service: {stderr}")
                raise Exception(f"Failed to restart Nginx service: {stderr}")

        else:
            logger.error(f"Unsupported server type: {type}")
            raise Exception(f"Unsupported server type: {type}")

        # Check status code and SSL expiry
        logger.info("Checking status code and SSL expiry...")
        if getStatusCode(dns) and get_ssl_expiry() > 30:
            logger.info("Certificate deployed successfully.")
            prod = True
            if type == 'apache2':
                rename_cert = vcert_commends.edit_conf_crt(ip='192.168.1.2',host_user='localhost',host_password='exist',prod=prod)
                run_command(rename_cert)
                rename_ca = vcert_commends.edit_conf_crt(ip='192.168.1.2',host_user='localhost',host_password='exist',prod=prod)
                run_command(rename_ca)
                rename_key = vcert_commends.edit_conf_ca(ip='192.168.1.2',host_user='localhost',host_password='exist',prod=prod)
                run_command(rename_key)
                run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} 'sudo systemctl restart apach2.service'")
            elif type == 'nginx':
                rename_cert = vcert_commends.edit_conf_crt(ip='192.168.1.2',host_user='localhost',host_password='exist',prod=prod)
                run_command(rename_cert)
                rename_key = vcert_commends.edit_conf_ca(ip='192.168.1.2',host_user='localhost',host_password='exist',prod=prod)
                run_command(rename_key)
                run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} 'sudo systemctl restart nginx.service'")
            return "Certificate deployed successfully"
        else:
            prod = False
            if type == 'apache2':
                rename_cert = vcert_commends.edit_conf_crt(ip='192.168.1.2',host_user='localhost',host_password='exist')
                run_command(rename_cert)
                rename_ca = vcert_commends.edit_conf_crt(ip='192.168.1.2',host_user='localhost',host_password='exist')
                run_command(rename_ca)
                rename_key = vcert_commends.edit_conf_ca(ip='192.168.1.2',host_user='localhost',host_password='exist')
                run_command(rename_key)
                run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} 'sudo systemctl restart apach2.service'")
                logger.error("Certificate deployment failed: Status code or SSL expiry check failed.")
                send_email_with_error_log()
            elif type == 'nginx':
                rename_cert = vcert_commends.edit_conf_crt(ip='192.168.1.2',host_user='localhost',host_password='exist')
                run_command(rename_cert)
                rename_ca = vcert_commends.edit_conf_crt(ip='192.168.1.2',host_user='localhost',host_password='exist')
                run_command(rename_key)
                run_command(f"sshpass -p '{host_password}' ssh {host_user}@{ip} 'sudo systemctl restart nginx.service'")
                logger.error("Certificate deployment failed: Status code or SSL expiry check failed.")
                send_email_with_error_log()
            return "Certificate deployment failed"

    except Exception as e:
        logger.error(f"An error occurred during deployment: {e}")
        send_email_with_error_log()
        return "Certificate deployment failed"
    



def dyploy_cert_netAPP(crt,key,rootca,dns):
    # cp crt
    execute_command(host=' ',port=22,username=' ',password=' ',command='pwd')
    # cp key
    execute_command(host=' ',port=22,username=' ',password=' ',command='pwd')
    # cp rootca
    execute_command(host=' ',port=22,username=' ',password=' ',command='pwd')
    # join crt and rootca to 1 file 
    execute_command(host=' ',port=22,username=' ',password=' ',command='pwd')
    # restart service
    execute_command(host=' ',port=22,username=' ',password=' ',command='pwd')
    # check status code
    if getStatusCode(dns) == True and get_ssl_expiry > 30:
        return "certoficate deployd successfully"
    else:
        send_email_with_error_log()
