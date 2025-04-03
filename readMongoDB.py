from pymongo import MongoClient
from dotenv import load_dotenv
import os


load_dotenv()
DBuser = os.getenv('DBuser')
DBpassword = os.getenv('DBpassword')
DBname = os.getenv('DBname')
DBip = os.getenv('DBip')
DBcollectionName = os.getenv('CollectionName')

class Mongo():

    def __init__(self,ip,DBname,CollectionName):
        self.ip = ip
        self.DBname = DBname

        # MongoDB connection setup
        #mongo_uri = f"mongodb://{encoded_username}:{encoded_password}@127.0.0.1:27017/"

        client = MongoClient(f"mongodb://{os.getenv('DBuser')}:{os.getenv('DBpassword')}@{ip}:27017/")  # Adjust as needed
        self.db = client[DBname]  # Replace with your DB name
        self.collection = self.db[CollectionName]  # Replace with your collection name
        


    def fetch_certificate(self,dns):
        """Fetch certificate details by dns."""
        cert_data = self.collection.find_one({"dns": dns})
        if cert_data:
            print(f"Certificate details fetched for {dns}")
            return cert_data
        else:
            print(f"No certificate found for {dns}")
            return None

    def write_certificate(self,id,name,fqdn,dns,ip,local,method=None,key=None,crt=None,chain=None):
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
        self.collection.insert_one(new_cert)
        print(f"New certificate added for {fqdn}")

    def edit_certificate(self,fqdn,id=None,name=None,dns=None,ip=None,local=None,method=None,key=None,crt=None,chain=None):
        """Edit an existing certificate by updating specific fields."""
        if not fqdn:
            print("FQDN is required to update a certificate.")
            return
        
        update_fields = {}
        if id: update_fields['id'] = id
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
        
        result = self.collection.update_one({"fqdn": fqdn}, {"$set": update_fields})
        
        if result.modified_count > 0:
            print(f"Certificate updated for {fqdn}")
        else:
            print(f"No updates made for {fqdn} (certificate may not exist).")

    def listCollection(self):
        for i in self.collection.find():
            print(i)

    def Collection2List(self):
        servers = []
        for i in self.collection.find():
            servers.append(i)
        return servers


    def Unset_column(self, field_name):
        """
        Removes a specified field (column) from all documents in the collection.
        :param field_name: The name of the field to remove.
        :return: A message indicating the result of the operation.
        """
        try:
            result = self.collection.update_many(
                {},  # Apply to all documents in the collection
                {"$unset": {field_name: ""}}  # Remove the specified field
            )
            return f"{result.modified_count} documents updated. Field '{field_name}' removed."
        except Exception as e:
            return f"An error occurred: {str(e)}"


    def Add_column(self, field_name, default_value=None):
        """
        Adds a specified field (column) to all documents in the collection with a default value.
        :param field_name: The name of the field to add.
        :param default_value: The default value to set for the new field (default is None).
        :return: A message indicating the result of the operation.
        """
        try:
            result = self.collection.update_many(
                {},  # Apply to all documents
                {"$set": {field_name: default_value}}  # Add field with default value
            )
            return f"{result.modified_count} documents updated. Field '{field_name}' added with default value '{default_value}'."
        except Exception as e:
            return f"An error occurred: {str(e)}"





"""
delete column
"""
# runner = Mongo(DBip,DBname,DBcollectionName)
# print(runner.Unset_column('id'))



"""
add column
"""
# runner = Mongo(DBip,DBname,DBcollectionName)
# print(runner.Add_column('Country',default_value="IL"))



























