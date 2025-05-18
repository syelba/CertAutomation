# vcert_commands.py

def ssl_expiry(domain, port):
    return f"""
    data=$(echo | openssl s_client -servername {domain} -connect {domain}:{port} 2>/dev/null | openssl x509 -noout -enddate | sed -e 's#notAfter=##')
    ssldate=$(date -d \"${{data}}\" '+%s')
    nowdate=$(date '+%s')
    diff=$((ssldate - nowdate))
    echo $((diff / 86400))
    """

def gen_csr(fqdn, city, state, country, dst):
    return f'sudo vcert gencsr --cn {fqdn} -o Intel --ou CCG -l {city} --st {state} -c {country} ' \
           f'--key-size 4096 --key-file {dst}/{fqdn}/{fqdn}.key --csr-file {dst}{fqdn}/{fqdn}.csr'

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


