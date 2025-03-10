import subprocess
import argparse 
import sys 





def get_ssl_expiry( port=443):
    domain = sys.argv[1]
    cmd = f"""
    data=$(echo | openssl s_client -servername {domain} -connect {domain}:{port} 2>/dev/null | openssl x509 -noout -enddate | sed -e 's#notAfter=##')
    ssldate=$(date -d "${{data}}" '+%s')
    nowdate=$(date '+%s')
    diff=$((ssldate - nowdate))
    echo $((diff / 86400))
    """
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        if result.returncode == 0:
            return int(result.stdout.strip())
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Exception: {e}"


days_left = get_ssl_expiry()

print(days_left)
