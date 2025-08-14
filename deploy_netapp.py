import re
from netmiko import ConnectHandler

def install_netapp_cert(
    host,
    username,
    password,
    vserver_name,
    site_dns,
    ca_name,
    cert_pem_path,
    cert_key_path,
    device_type="terminal_server"  # or "netapp_cdot" if your Netmiko version supports it
):
    # --- Read cert and split blocks ---
    with open(cert_pem_path, "r") as f:
        pem_data = f.read()

    cert_blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_data,
        re.DOTALL
    )

    if len(cert_blocks) < 3:
        raise ValueError("Expected at least 3 certificates in cert.pem")

    cert1, cert2, cert3 = cert_blocks[0], cert_blocks[1], cert_blocks[2]

    # --- Read private key ---
    with open(cert_key_path, "r") as f:
        key_var = f.read()

    # --- Connect to NetApp ---
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    conn = ConnectHandler(**device)

    # --- Start cert install ---
    cmd = f"security certificate install -type server -vserver {vserver_name}"
    output = conn.send_command_timing(cmd)

    # Send first cert
    output += conn.send_command_timing(cert1)
    output += conn.send_command_timing("")  # Enter

    # Send key
    output += conn.send_command_timing(key_var)
    output += conn.send_command_timing("")  # Enter
    output += conn.send_command_timing("y") # Confirm if asked

    # Send second cert
    output += conn.send_command_timing(cert2)
    output += conn.send_command_timing("")  # Enter
    output += conn.send_command_timing("")  # Extra Enter
    output += conn.send_command_timing("y") # Confirm if asked

    # Send third cert
    output += conn.send_command_timing(cert3)
    output += conn.send_command_timing("")  # Enter
    output += conn.send_command_timing("")  # Extra Enter

    # --- Extract serial number ---
    serial_match = re.search(r"serial:\s*([A-F0-9]+)", output, re.IGNORECASE)
    if not serial_match:
        conn.disconnect()
        raise ValueError("Could not find serial number in output")

    serial_number = serial_match.group(1)
    print(f"[INFO] Extracted Serial: {serial_number}")

    # --- Modify SSL with new cert ---
    ssl_cmd = (
        f"security ssl modify -vserver {vserver_name} "
        f"-common-name {site_dns} "
        f"-serial {serial_number} "
        f"-ca \"{ca_name}\" "
        f"-server-enabled true -client-enabled true"
    )
    conn.send_command(ssl_cmd)

    conn.disconnect()
    return serial_number
