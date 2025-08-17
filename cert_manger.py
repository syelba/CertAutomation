
from venafy_client_v2 import CertificateRenewal
from deploy_cert_v2 import CertificateDeployer
from EditMongoDB import Mongo

class cert_manager:
    def __init__(self,CertificateRenewal,CertificateDeployer):
        self.CertificateDeployer = CertificateDeployer
        self.CertificateRenewal = CertificateRenewal

    def renew_full(self):
        pass

    def renew_one(self):
        pass

    







