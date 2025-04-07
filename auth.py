import os
import subprocess
import logging
from datetime import datetime
from dotenv import load_dotenv
import config




# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(filename="log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
#logging.warning(warning_msg)
#logging.error(error_msg)
#logging.info(f"vcert getcred output: {output}")



def checkExpiration(expiration_time):
    """Check if the token expires within 30 days."""
    try:
        exp_datetime = datetime.strptime(expiration_time, "%Y-%m-%dT%H:%M:%SZ")
        current_time = datetime.utcnow()
        days_remaining = (exp_datetime - current_time).days
        
        if days_remaining < config.days_remain:
            warning_msg = f"⚠️ Warning: Token expires in {days_remaining} days! Renew soon."
            print(warning_msg)
            logging.warning(warning_msg)
            # Send mail here (optional)
        else:
            valid_msg = f"Token is valid for {days_remaining} more days."
            print(valid_msg)
            logging.info(valid_msg)
        
        return days_remaining
    except Exception as e:
        error_msg = f"Error parsing expiration time: {str(e)}"
        print(error_msg)
        logging.error(error_msg)
        return None

def get_venafi_token():
    """Run `vcert getcred` and extract the access token and expiration date."""
    try:
        result = subprocess.run(
            ["vcert", "getcred", "--u", os.getenv('venafiURL'), "--username",
             os.getenv('SysAdminUser'), "--password", os.getenv('SysPassword')],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        logging.info(f"vcert getcred output: {output}")
        
        token_parts = output.split()
        token = token_parts[1]
        expire_time = token_parts[3]
        checkExpiration(expire_time)
        return token
    except subprocess.CalledProcessError as e:
        error_msg = f"Error running vcert getcred: {e.stderr}"
        print(error_msg)
        logging.error(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(error_msg)
        logging.error(error_msg)


