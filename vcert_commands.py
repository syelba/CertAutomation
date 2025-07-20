# vcert_commands.py

def ssl_expiry(domain, port):
    return f"""
    data=$(echo | openssl s_client -servername {domain} -connect {domain}:{port} 2>/dev/null | openssl x509 -noout -enddate | sed -e 's#notAfter=##')
    ssldate=$(date -d \"${{data}}\" '+%s')
    nowdate=$(date '+%s')
    diff=$((ssldate - nowdate))
    echo $((diff / 86400))
    """

#sudo vcert gencsr --cn elitpts41.iil.intel.com -o Intel --ou CCG -l PTK --st Israel -c IL --key-size 4096 --key-file elitpts41.iil.intel.com.key --csr-file elitpts41.iil.intel.com.csr
def gen_csr(fqdn, city, state, country, dst):
    return f'sudo vcert gencsr --cn {fqdn} -o Intel --ou CCG -l {city} --st {state} \
            -c {country} --key-size 4096 --key-file {dst}/{fqdn}/{fqdn}_test.key --csr-file {dst}{fqdn}/{fqdn}.csr'


def windows_crt_renew(token, venafiURL, fqdn, id, dst, pfxpassword):
    return f'sudo vcert renew -t {token} -u {venafiURL} --file {dst}/{fqdn}/{fqdn}.pfx ' \
           f'--format pkcs12 --chain ignore --verbose --id "{id}" -csr service --key-password {pfxpassword}'

def renew_apache_nginx(token, venafiURL, fqdn, id, dst):
    return f'sudo vcert renew -t "{token}" -u {venafiURL} --id "{id}" --csr file:{dst}/{fqdn}/{fqdn}.csr'

def renew_netapp(token, venafiURL, fqdn, id, dst):
    return f'sudo vcert renew -t {token} -u {venafiURL} --file {dst}/{fqdn}/{fqdn}.pem -id "{id}" --csr file:{dst}/{fqdn}/{fqdn}.csr'


def pickup_apache_nginx(token, venafiURL, fqdn, id, dst):
    return f'sudo vcert pickup -u {venafiURL} -t {token} --pickup-id "{id}" ' \
           f'--cert-file {dst}{fqdn}/{fqdn}.crt --chain-file {dst}{fqdn}/IntelSHA256RootCA.crt'

#pass
def edit_conf_crt(fqdn,conf_file,prod = False):
    test = '_test'
    if prod:
        return f"sudo rm {fqdn}.crt && sudo mv {fqdn}{test}.crt {fqdn}.crt && sudo sed -i -e 's/{fqdn}{test}.crt/{fqdn}.crt/g' {conf_file}"
    
#pass
def edit_conf_ca(conf_file,prod = False):
    test = '_test'
    if prod:
        return f"sudo rm IntelSHA256RootCA.crt && sudo mv IntelSHA256RootCA{test}.crt IntelSHA256RootCA.crt && \
        sudo sed -i -e 's/IntelSHA256RootCA{test}.crt/IntelSHA256RootCA.crt/g' {conf_file}"


def edit_conf_key(fqdn,conf_file,prod = False):
    test = '_test'
    if prod:
        return f"sudo rm {fqdn}.crt && sudo mv {fqdn}{test}.crt && sudo sed -i -e 's/{fqdn}{test}.key/{fqdn}.key/g' {conf_file}"
    


def restart_service(method):
    return f"sudo systemctl restart {method}.service"

def full_chain_file(fqdn):
    return  f"cat {fqdn}_test.crt IntelSHA256RootCA_test.crt > fullchain_test.crt"


def mov_to_opt(method,fqdn):
    if method == "apach2":
        return f"sudo mv {fqdn}_test.crt /opt/cert/. &&"\
            f"sudo mv {fqdn}_test.key /opt/cert/. &&"\
            f"sudo mv IntelSHA256RootCA_test.crt /opt/cert/. "
    else:
        return  f"sudo mv fullchain_test.crt /opt/cert/. &&"\
                f"sudo mv {fqdn}_test.key /opt/cert/. &&"\
                f"sudo mv IntelSHA256RootCA_test.crt /opt/cert/. "
    


#use must provide conf path , and path for crt location 
def move_to_path(path,fqdn,method):
    if method == "apach2":
        return f"sudo mv {fqdn}_test.crt {path}/. &&"\
                f"sudo mv {fqdn}_test.key {path}/. &&"\
                f"sudo mv IntelSHA256RootCA_test.crt {path}/. "
    else:
        return  f"sudo mv fullchain_test.crt {path}/. &&"\
                f"sudo mv {fqdn}_test.key {path}/. &&"\
                f"sudo mv IntelSHA256RootCA_test.crt {path}/. "
