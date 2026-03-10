from utils.network_utils.base.Network import Network
from datetime import datetime, timezone
import asyncio
from pathlib import Path
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

class PacketCapture(Network):
    def __init__(self):
        super().__init__()
        
    def set_host(self, host: str):
        self.host = host

    def set_credentials(self, user: str, password: str):
        self.user = user
        self.password = password

    async def pcap_remote_linux(self, remote_iface: str, cap_count: int = 50):
        time_stamp = datetime.now(timezone.utc).isoformat()
        pcap_file_name = f"{self.host}_capture_{time_stamp}.pcap"

        pcap_cmd = f"cd /home/{self.user} && tcpdump -i {remote_iface} -s0 -c {cap_count} -w {pcap_file_name}"
        copy_cmd = f"sshpass -p '{self.password}' rsync -avzP -e ssh {self.user}@{self.host}:/home/{self.user}/{pcap_file_name} /home/quart/probedata/pcaps"
        
        init_code, init_output, init_error = await self.ssh_connect(host=self.host, user=self.user, password=self.password)
        if init_code != 0:
            logger.info(init_output)
            logger.info(init_error)
            return 1
        
        ssh_code, ssh_output, ssh_error = await self.run_ssh_cmd(host=self.host, user=self.user, password=self.password, cmd=pcap_cmd)
        if ssh_code != 0:
            logger.info(ssh_output)
            logger.info(ssh_error)
            return 1
        
        shell_code, shell_output, shell_error = await self.run_shell_cmd(cmd=copy_cmd)

        return shell_code, shell_output, shell_error

    async def pcap_remote_windows(self, remote_iface: str, duration: int = 30):
        time_stamp = datetime.now(timezone.utc).isoformat()
        OUTPUT_DIR = Path("/home/quart/probedata/pcaps")
        pcap_file_name = OUTPUT_DIR / f"{self.host}_capture_{time_stamp}.pcap"

        TSHARK_PATH=f'C:\Program Files\Wireshark\tshark.exe'
        DURATION = duration  # seconds

        pcap_cmd = f"'{TSHARK_PATH}' -D && '{TSHARK_PATH}' -i {remote_iface} -a duration:{DURATION}"

        command = (
            f"sshpass -p '{self.password}' ssh -C -tt -o StrictHostKeyChecking=no "
            f"{self.user}@{self.host} '{pcap_cmd}'"
            )
       
        await self.ssh_connect(host=self.host, user=self.user, password=self.password)

        proc = await asyncio.create_subprocess_exec(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            with pcap_file_name.open("wb") as f:
                while True:
                    chunk = await proc.stdout.read(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)

            stderr = await proc.stderr.read()
            if stderr:
                logger.error(f"[!] tshark stderr:\n{stderr.decode(errors='ignore')}")

        finally:
            stdout, stderr = await proc.communicate()
    
            self.logger.error(stderr.decode())
        
            self.logger.info(stdout.decode())

            return_code = await proc.wait()

        return return_code, stdout, stderr

    async def pcap_local(self, interface: str, cap_count: int = 50):
        time_stamp = datetime.now(timezone.utc).isoformat()
        pcap_file_name = f"/home/quart/probedata/pcaps/{self.host}_capture_{time_stamp}.pcap"
        pcap_cmd = f"tcpdump -i {interface} -s0 -c {cap_count} -w {pcap_file_name}"
        
        code, output, error = await self.run_shell_cmd(cmd=pcap_cmd)

        return code, output, error

        



