from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust as needed
db = client["assets"]  # Replace with your DB name
collection = db["certificates"]  # Replace with your collection name

def fetch_certificate(dns):
    """Fetch certificate details by dns."""
    cert_data = collection.find_one({"dns": dns})
    if cert_data:
        print(f"Certificate details fetched for {dns}")
        return cert_data
    else:
        print(f"No certificate found for {dns}")
        return None

def write_certificate(id,name,fqdn,dns,ip,local,method=None,key=None,crt=None,chain=None):
    """Add a new certificate to the database."""
    if not (id and name and fqdn and dns and ip and local):
        print("All fields are required to add a new certificate.")
        return

    new_cert = {
            "id": id,
            "name": name,
            "fqdn": fqdn,
            "dns": dns,
            "ip": ip,
            "local": local,
            "key" : key,
            "crt" : crt,
            "chain" : chain,
            "method": method
        }
    collection.insert_one(new_cert)
    print(f"New certificate added for {fqdn}")

def edit_certificate(fqdn,id=None,name=None,dns=None,ip=None,local=None,method=None,key=None,crt=None,chain=None):
    """Edit an existing certificate by updating specific fields."""
    if not fqdn:
        print("FQDN is required to update a certificate.")
        return
    
    update_fields = {}
    if id: update_fields["id"] = id
    if name: update_fields["name"] = name
    if dns: update_fields["dns"] = dns
    if ip: update_fields["ip"] = ip
    if local: update_fields["local"] = local
    if method: update_fields["method"] = method
    if key: update_fields["key"] = key
    if crt: update_fields["crt"] = crt
    if chain: update_fields["chain"] = chain
    
    if not update_fields:
        print("No fields provided for update.")
        return
    
    result = collection.update_one({"fqdn": fqdn}, {"$set": update_fields})
    
    if result.modified_count > 0:
        print(f"Certificate updated for {fqdn}")
    else:
        print(f"No updates made for {fqdn} (certificate may not exist).")


apps = [
        {
            "id": "26331",
            "name": "wcs lab market",
            "fqdn": "JESMarket.ger.corp.intel.com",
            "dns": "wcsmarket.intel.com",
            "ip": "10.12.176.21",
            "local": "Jerusalem",
            "key":"server.key",
            "crt":"server.crt",
            "chain":"Intel",
            "method": "apache2"
        },
        {
            "id": "35231",
            "name": "HVPIP survey app",
            "fqdn": "jeshvpip.iil.intel.com",
            "dns": "hvpip.iil.intel.com",
            "ip": "10.12.176.19",
            "local": "Jerusalem"
        },
        {
            "id": "25275",
            "name": "isd.iil.intel.com",
            "fqdn": "JESWEBDEV.ger.corp.intel.com",
            "dns": "isd.iil.intel.com",
            "ip": "10.12.176.22",
            "local": "Jerusalem"
        },
        {
            "id": "26924",
            "name": "WCS VMware ESX and vCenter",
            "fqdn": "idcvm-vc.iil.intel.com",
            "dns": "idcvm-vc.iil.intel.com",
            "ip": "10.185.11.10",
            "local": "Haifa"
        },
        {
            "id": "26924",
            "name": "WCS VMware ESX and vCenter",
            "fqdn": "ptkvm-vc.iil.intel.com",
            "dns": "ptkvm-vc.iil.intel.com",
            "ip": "10.189.180.11",
            "local": "Petah Tikva"
        },
        {
            "id": "39499",
            "name": "Central Dash",
            "fqdn": "jescentrald.iil.intel.com",
            "dns": "digital-lab.intel.com",
            "ip": "10.12.176.16",
            "local": "Jerusalem"
        },
        {
            "id": "38837",
            "name": "Ops dashbord",
            "fqdn": "JEDNIR01.iil.intel.com",
            "dns": "JEDNIR02.iil.intel.com",
            "ip": "10.12.216.148",
            "local": "Jerusalem"
        },
        {
            "id": "38676",
            "name": "Purchasing Requests - Ops Review Report",
            "fqdn": "JEDiLS09.iil.intel.com",
            "dns": "JEDiLS09.iil.intel.com",
            "ip": "10.12.191.128",
            "local": "Jerusalem"
        },
        {
            "id": "26926",
            "name": "WCS NetAPP Storage",
            "fqdn": "ptkc03.iil.intel.com",
            "dns": "ptkc03.iil.intel.com",
            "ip": "10.189.186.36"
        },
        {
            "id": "36225",
            "name": "Utilization Dashboard",
            "fqdn": "JESUtilize.jer.intel.com",
            "dns": "utilization.intel.com",
            "ip": "10.12.176.10",
            "local": "Jerusalem"
        },
        {
            "id": "38323",
            "name": "JER Platform Parts Placement Form",
            "fqdn": "jespstop.iil.intel.com",
            "dns": "pitstop.intel.com",
            "dns2": "blrsrr-pitstop.iind.intel.com",
            "ip": "10.12.176.30",
            "local": "Jerusalem"
        },
         {
            "id": "39891",
            "name": "Optimus",
            "fqdn": "elitpts65.iil.intel.com",
            "dns": "optimus.intel.com",
            "ip": "10.189.180.65",
            "local": "Haifa"
        },
          {
            "id": "33722",
            "name": "squidserver",
            "fqdn": "IDCVM-iLSTools.iil.intel.com",
            "dns": "ilsrvp.intel.com",
            "ip": "10.185.11.62",
            "local": "Haifa"
        },
        
        {
            "id": "25705",
            "name": "isquid",
            "fqdn": "elitpts41.iil.intel.com",
            "dns": "isquid.intel.com",
            "ip": "10.189.180.41",
            "local": "Petah Tikva"
        },
        {
            "id": "38427",
            "name": "Zabbix_ILS",
            "fqdn": "JESZabbix.iil.intel.com",
            "dns": "JESZabbix.iil.intel.com",
            "ip": "10.12.176.13",
            "local": "Jerusalem"
        },
        {
            "id": "38427",
            "name": "Zabbix_ILS",
            "fqdn": "idcvm-zabbix.iil.intel.com",
            "dns": "idcvm-zabbix.iil.intel.com",
            "ip": "10.185.11.128",
            "local": "Haifa"
        },
        {
            "id": "38427",
            "name": "Zabbix_ILS",
            "fqdn": "SRR4-VM-ZABBIX.iil.intel.com",
            "dns": "SRR4-VM-ZABBIX.iil.intel.com",
            "ip": "10.66.225.185",
            "local": "Bangalore"
        },
        {
            "id": "36904",
            "name": "WCS NetAPP ActiveIQ Unified Manager",
            "fqdn": "JESAIQUM.iil.intel.com",
            "dns": "JESAIQUM.iil.intel.com",
            "ip": "10.12.176.92",
            "local": "Jerusalem"
        },
    ]




for i in range(len(apps)):
    print(apps[i])
    write_certificate(id=apps[i]['id'],name=apps[i]['name'],fqdn=apps[i]['fqdn'],dns=apps[i]['dns'],ip=apps[i]['ip'],local=apps[i]['local'],
                      method=apps[i]['method'],key=apps[i]['key'],crt=apps[i]['crt'],chain=apps[i]['chain'])







# # Renew the certificate
# try:
#     vcert_client.renew_certificate(
#         cert_id=cert_id,
#         key_file=key_path,
#         cert_file=crt_path,
#         chain_file="company_chain.crt",  # If applicable
#         method=method
#     )
#     print(f"Certificate for {fqdn} renewed successfully.")
# except VCertError as e:
#     print(f"Error renewing certificate: {str(e)}")





# # Update the MongoDB entry with the new certificate details
# updated_data = {
#     "crt": "server_new.crt",  # Update with the new certificate file path
#     "key": "server_new.key",  # Update with the new private key path
#     "renewed_at": datetime.utcnow()
# }

# # Update the record in MongoDB
# collection.update_one({"fqdn": fqdn}, {"$set": updated_data})
# print(f"Certificate for {fqdn} updated in MongoDB.")
