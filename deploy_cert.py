from utils import run_command,scp_upload, send_email_with_error_log,get_ssl_expiry,getStatusCode,execute_command
import os 
from dotenv import load_dotenv
import time
from loguru import logger
from datetime import datetime
load_dotenv()
import vcert_commends
import os.path
import asyncssh
import asyncio


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
    def __init__(self, ip, host_user, host_password,conf_path, crt, key, rootca, dns, fqdn, method):
        self.ip = ip
        self.host_user = host_user
        self.host_password = host_password
        self.crt = crt
        self.key = key
        self.rootca = rootca
        self.dns = dns
        self.fqdn = fqdn
        self.method = method
        self.conf_path = conf_path
        self.path = os.getenv('dst') + fqdn
        if os.path.isdir(self.path):
            logger.info(f'path {self.path} is valid')
            print(f'path {self.path} is valid')
        else:
            logger.error(f'the path {self.path} is not valid')
            print(f'the path {self.path} is not valid')

    def _run(self, command):
        """
        execute any command on target machine
        """
        return asyncio.run(execute_command(hostname=self.ip,username=self.host_user,password=self.host_password,command=command))

    def _copy_file(self, src_file, dest_file):
        """
        upload crt file/any file to server
        """
        #command = f"sshpass -p '{self.host_password}' scp {src_file} {self.host_user}@{self.ip}:{dest_file}"
        asyncio.run(scp_upload(self.ip,self.host_user,self.host_password,local_path=src_file,remote_path=dest_file))

    def _edit_config(self, search, replace):
        """
        edit target conf file
        """
        command = f"sudo sed -i -e 's/{search}/{replace}/g' {self.conf_path}"
        #command = vcert_commends.
        return  self._run(command)
        

    def restart_service(self):
        """
        restart the service on target machine , by method running on web server
        """
        build_commend = vcert_commends.restart_service(self.method)
        res = asyncio.run(execute_command(hostname=self.ip,username=self.host_user,password=self.host_password,command=build_commend))
        return res

    def _post_deploy_actions(self, prod):
        rename_cert = vcert_commends.edit_conf_crt(prod=prod)
        rename_ca = vcert_commends.edit_conf_key(prod=prod)
        rename_key = vcert_commends.edit_conf_ca(prod=prod)
        self._run(rename_cert)
        self._run(rename_ca)
        self._run(rename_key)
        self.restart_service("apache2" if self.method == "apache2" else "nginx")


    def deploy_apache(self):
        """
        this is step after coping the files to the server 
        1.for apache2 : creating 1 file from rootCA and crt file 
        2. edit conf file and test the crt
        """ 
        logger.info("Deploying to Apache2...")
        self._edit_config(f'{self.fqdn}_test.crt', f'{self.fqdn}.crt',self.conf_path)
        self._edit_config(f'IntelSHA256RootCA_test.crt', f'IntelSHA256RootCA.crt',self.conf_path)
        self._edit_config(f'{self.fqdn}_test.key', f'{self.fqdn}.key',self.conf_path)
        self.restart_service('apache2')


    def deploy_nginx(self):
        """
        this is step after coping the files to the server 
        1.for nginx : creating 1 file from rootCA and crt file 
        2. edit conf file and test the crt
        """ 
        logger.info("Creating fullchain certificate for Nginx...")
        cmd = vcert_commends.full_chain_file(self.fqdn)
        res = self._run(cmd)
        self._edit_config('fullchain_test.key', 'fullchain.key')
        self._edit_config(f'{self.fqdn}_test.key', f'{self.fqdn}.key')
        self.restart_service('nginx')
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
            #copy to user 
            logger.info("Copying certificate...")
            self._copy_file(f"{self.path}/{self.fqdn}_test.crt", f"{self.crt}/")
            logger.info("Copying key...")
            self._copy_file(f"{self.path}/{self.fqdn}_test.key", f"{self.rootca}/")
            logger.info("Copying root CA...")
            self._copy_file(f"{self.path}/IntelSHA256RootCA_test.crt", f"{self.key}/")

            if self.method == 'apache2':
                self.deploy_apache()
            elif self.method == 'nginx':
                self.deploy_nginx()
            else:
                raise Exception(f"Unsupported server type: {self.method}")

            #move to opt/crt
            logger.info("Checking status code and SSL expiry...")
            if getStatusCode(self.dns) and get_ssl_expiry() > 30:
                logger.info("Certificate deployed successfully.")
                # self._post_deploy_actions(prod=True)
                return "Certificate deployed successfully"
            else:
                logger.error("Certificate deployment failed: Status code or SSL expiry check failed.")
                # self._post_deploy_actions(prod=False)
                # send_email_with_error_log()
                # return "Certificate deployment failed"

        except Exception as e:
            logger.error(f"An error occurred during deployment: {e}")
            # send_email_with_error_log()
            return "Certificate deployment failed"
