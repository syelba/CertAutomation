from pydantic import BaseModel, Field, root_validator
from typing import Optional
from pymongo import MongoClient
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()
DBuser = os.getenv('DBuser')
DBpassword = os.getenv('DBpassword')
DBname = os.getenv('DBname')
DBip = os.getenv('DBip')
DBcollectionName = os.getenv('CollectionName')


class CertificateModel(BaseModel):
    id: Optional[str] = Field(None, description="Unique identifier for the certificate")
    name: Optional[str] = Field("Unknown", description="Name of the certificate")
    fqdn: str = Field(..., description="Fully Qualified Domain Name")
    dns: str = Field(..., description="DNS of the certificate")
    ip: str = Field(..., description="IP address associated with the certificate")
    local: str = Field(..., description="Local information")
    method: Optional[str] = Field(None, description="Method used for the certificate")
    key: Optional[str] = Field(None, description="Key of the certificate")
    crt: Optional[str] = Field(None, description="Certificate data")
    chain: Optional[str] = Field(None, description="Certificate chain")
    pickup_ID: Optional[str] = Field(None, description="Pickup ID for the certificate")
    state: Optional[str] = Field(None, description="state of server")
    Country: Optional[str] = Field(None, description="2 letter Country code")

    @root_validator(pre=True)
    def handle_mongo_id(cls, values):
        values.pop("_id", None)
        if "id" not in values or not values["id"]:
            values["id"] = None
        if "name" not in values or not values["name"]:
            values["name"] = "Unknown"
        if "pickup-ID" in values:
            values["pickup_ID"] = values.pop("pickup-ID")
        return values


class Mongo:
    def __init__(self):
        client = MongoClient(f"mongodb://{DBuser}:{DBpassword}@{DBip}:27017/")
        self.db = client[DBname]
        self.collection = self.db[DBcollectionName]

    def fetch_certificate(self, dns: str) -> Optional[CertificateModel]:
        cert_data = self.collection.find_one({"dns": dns})
        if cert_data:
            print(f"Certificate details fetched for {dns}")
            return CertificateModel(**cert_data)
        else:
            print(f"No certificate found for {dns}")
            return None

    def write_certificate(self, cert: CertificateModel):
        self.collection.insert_one(cert.dict())
        print(f"New certificate added for {cert.fqdn}")

    def check_and_update_or_insert_certificate(self, cert: CertificateModel):
        self.collection.update_one(
            {"fqdn": cert.fqdn},
            {"$set": cert.dict()},
            upsert=True
        )
        print(f"Certificate upserted for {cert.fqdn}")

    def edit_certificate(self, fqdn: str, **kwargs):
        if not fqdn:
            print("FQDN is required to update a certificate.")
            return

        update_fields = {k: v for k, v in kwargs.items() if v is not None}
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

    def Collection2List(self) -> list[CertificateModel]:  # or List[CertificateModel] for Python <3.9
        return [CertificateModel(**i) for i in self.collection.find()]

    def Unset_column(self, field_name: str) -> str:
        try:
            result = self.collection.update_many({}, {"$unset": {field_name: ""}})
            return f"{result.modified_count} documents updated. Field '{field_name}' removed."
        except Exception as e:
            return f"An error occurred: {str(e)}"

    def Add_column(self, field_name: str, default_value=None) -> str:
        try:
            result = self.collection.update_many({}, {"$set": {field_name: default_value}})
            return f"{result.modified_count} documents updated. Field '{field_name}' added with default value '{default_value}'."
        except Exception as e:
            return f"An error occurred: {str(e)}"
