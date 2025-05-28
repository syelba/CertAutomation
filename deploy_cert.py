from utils import run_command, send_email_with_error_log,get_ssl_expiry,getStatusCode,execute_command
import os 
from dotenv import load_dotenv
import time
from loguru import logger
from datetime import datetime
load_dotenv()
import vcert_commends
import os.path

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





class CertificateDeployer:
    def __init__(self, ip, host_user, host_password, crt, key, rootca, dns, fqdn, server_type):
        self.ip = ip
        self.host_user = host_user
        self.host_password = host_password
        self.crt = crt
        self.key = key
        self.rootca = rootca
        self.dns = dns
        self.fqdn = fqdn
        self.server_type = server_type
        self.path = os.getenv('dst') + fqdn
        if os.path.isdir(self.path):
            logger.info(f'path {self.path} is valid')
            print(f'path {self.path} is valid')
        else:
            logger.error(f'the path {self.path} is not valid')
            print(f'the path {self.path} is not valid')

    def _run(self, command):
        return run_command(command)

    def _copy_file(self, src_file, dest_file):
        command = f"sshpass -p '{self.host_password}' scp {src_file} {self.host_user}@{self.ip}:{dest_file}"
        stdout, stderr, code = self._run(command)
        if code != 0:
            raise Exception(f"Failed to copy {os.path.basename(src_file)}: {stderr}")

    def _edit_config(self, search, replace):
        command = f"sshpass -p '{self.host_password}' ssh {self.host_user}@{self.ip} sudo sed -i -e 's/{search}/{replace}/g' /etc/nginx/sites-available/certapp"
        command = vcert_commends.
        stdout, stderr, code = self._run(command)
        if code != 0:
            raise Exception(f"Failed to edit config: {stderr}")

    def _restart_service(self, service):
        command = vcert_commends.restart_service(self.ip,self.host_user,self.host_password,service)
        stdout, stderr, code = self._run(command)
        if code != 0:
            logger.error(f"Failed to restart {service}: {stderr}")
            raise Exception(f"Failed to restart {service}: {stderr}")

    def _post_deploy_actions(self, prod):
        import vcert_commends
        rename_cert = vcert_commends.edit_conf_crt(ip='192.168.1.2', host_user='localhost', host_password='exist', prod=prod)
        rename_ca = vcert_commends.edit_conf_crt(ip='192.168.1.2', host_user='localhost', host_password='exist', prod=prod)
        rename_key = vcert_commends.edit_conf_ca(ip='192.168.1.2', host_user='localhost', host_password='exist', prod=prod)
        self._run(rename_cert)
        self._run(rename_ca)
        self._run(rename_key)
        self._restart_service("apache2" if self.server_type == "apache2" else "nginx")

    def deploy_apache(self):
        logger.info("Deploying to Apache2...")
        self._edit_config('certAutomation_test.key', 'certAutomation.key')
        self._edit_config('certAutomation.key', 'certAutomation_test.key')
        self._restart_service('apache2')

    def deploy_nginx(self):
        logger.info("Creating fullchain certificate for Nginx...")
        cmd = f"sshpass -p '{self.host_password}' ssh {self.host_user}@{self.ip} 'cat {self.fqdn}_test.crt IntelSHA256RootCA.crt > fullchain_test.crt'"
        stdout, stderr, code = self._run(cmd)
        if code != 0:
            raise Exception(f"Failed to create fullchain certificate: {stderr}")
        self._edit_config('certAutomation_test.key', 'certAutomation.key')
        self._edit_config('certAutomation.key', 'certAutomation_test.key')
        self._restart_service('nginx')
######################################################################################################################################################################
    def deploy(self):
        """
        main function copy files by default 
        and try to edit conf file 
        and restart service
        check if working if so
        change coping files to original files
        if not working revert to old cert files
        """
        try:
            logger.info(f"Starting certificate deployment for {self.fqdn} on {self.ip}")

            logger.info("Copying certificate...")
            self._copy_file(f"{self.path}/{self.fqdn}_test.crt", f"/home/{self.host_user}/")
            logger.info("Copying key...")
            self._copy_file(f"{self.path}/{self.fqdn}_test.key", f"/home/{self.host_user}/")
            logger.info("Copying root CA...")
            self._copy_file(f"{self.path}/IntelSHA256RootCA.crt", f"/home/{self.host_user}/")

            if self.server_type == 'apache2':
                self.deploy_apache()
            elif self.server_type == 'nginx':
                self.deploy_nginx()
            else:
                raise Exception(f"Unsupported server type: {self.server_type}")

            logger.info("Checking status code and SSL expiry...")
            if getStatusCode(self.dns) and get_ssl_expiry() > 30:
                logger.info("Certificate deployed successfully.")
                self._post_deploy_actions(prod=True)
                return "Certificate deployed successfully"
            else:
                logger.error("Certificate deployment failed: Status code or SSL expiry check failed.")
                self._post_deploy_actions(prod=False)
                send_email_with_error_log()
                return "Certificate deployment failed"

        except Exception as e:
            logger.error(f"An error occurred during deployment: {e}")
            send_email_with_error_log()
            return "Certificate deployment failed"
