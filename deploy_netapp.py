import asyncio
import asyncssh
import re

async def install_netapp_cert(host, username, password, vserver_name, site_dns, cert_pem_path, cert_key_path):
    # --- Read cert and split blocks ---
    with open(cert_pem_path, "r") as f:
        pem_data = f.read()
    cert_blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_data, re.DOTALL)
    if len(cert_blocks) < 3:
        raise ValueError("Expected at least 3 certificates in cert.pem")
    cert1, cert2, cert3 = cert_blocks[0], cert_blocks[1], cert_blocks[2]

    # --- Read private key ---
    with open(cert_key_path, "r") as f:
        key_var = f.read()

    # --- Connect ---
    async with asyncssh.connect(host, username=username, password=password, known_hosts=None) as conn:
        process = await conn.create_process(term_type='xterm')

        output = ""

        async def send_input(data):
            process.stdin.write(data + "\n")

        # Read output continuously
        async def read_output():
            nonlocal output
            async for line in process.stdout:
                print(line, end="")  # live CLI output
                output += line

        # Start reading output in background
        reader_task = asyncio.create_task(read_output())

        # Send commands step by step
        await send_input(f"security certificate install -type server -vserver {vserver_name}")
        await asyncio.sleep(1)
        await send_input(cert1)
        await send_input("")  # Enter
        await asyncio.sleep(1)
        await send_input(key_var)
        await send_input("")  # Enter
        await send_input("y")
        await asyncio.sleep(1)
        await send_input(cert2)
        await send_input("")  # Enter
        await send_input("")  # Enter
        await send_input("y")
        await asyncio.sleep(1)
        await send_input(cert3)
        await send_input("")  # Enter
        await send_input("")  # Enter
        await send_input("n")
        await asyncio.sleep(2)  # wait for final output

        # Cancel reader
        reader_task.cancel()
        try:
            await reader_task
        except asyncio.CancelledError:
            pass

        # Extract serial number
        serial_match = re.search(r"serial:\s*([A-F0-9]+)", output, re.IGNORECASE)
        serial_number = serial_match.group(1) if serial_match else None
        print(f"[INFO] Serial: {serial_number}")

        if serial_number:
            ssl_cmd = (
                f"security ssl modify -vserver {vserver_name} "
                f"-common-name {site_dns} "
                f"-serial {serial_number} "
                f"-ca \"Intel Internal Issuing CA 5A\" "
                f"-server-enabled true -client-enabled true"
            )
            await send_input(ssl_cmd)

    return "done"



