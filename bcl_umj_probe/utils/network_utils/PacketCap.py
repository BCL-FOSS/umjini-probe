from base.Network import Network
from datetime import datetime, timedelta, timezone
import asyncio
from pathlib import Path
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

class PacketCap(Network):
    def __init__(self, host: str, user: str, password: str):
        super().__init__()
        self.host = host
        self.user = user
        self.password = password

    async def pcap_remote_linux(self, remote_iface: str, cap_count: int = 50):
        time_stamp = datetime.now(timezone.utc).isoformat()
        pcap_file_name = f"{self.host}_capture_{time_stamp}.pcap"

        pcap_cmd = f"cd /home/{self.user} && tcpdump -i {remote_iface} -s0 -c {cap_count} -w {pcap_file_name}"
        copy_cmd = f"sshpass -p '{self.password}' rsync -avzP -e ssh {self.user}@{self.host}:/home/{self.user}/{pcap_file_name} /home/quart/probedata/pcaps"
        
        await self.ssh_connect(host=self.host, user=self.user, password=self.password)
        await self.run_ssh_cmd(host=self.host, user=self.user, password=self.password, cmd=pcap_cmd)
        await self.run_shell_cmd(cmd=copy_cmd)

    async def pcap_remote_windows(self, remote_iface: str):
        time_stamp = datetime.now(timezone.utc).isoformat()
        OUTPUT_DIR = Path("/home/quart/probedata/pcaps")
        pcap_file_name = OUTPUT_DIR / f"{self.host}_capture_{time_stamp}.pcap"

        TSHARK_PATH=f'C:\Program Files\Wireshark\tshark.exe'
        DURATION = 30  # seconds

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
            await proc.wait()

    async def pcap_local(self, interface: str, cap_count: int = 50):
        time_stamp = datetime.now(timezone.utc).isoformat()
        pcap_file_name = f"/home/quart/probedata/pcaps/{self.host}_capture_{time_stamp}.pcap"
        pcap_cmd = f"tcpdump -i {interface} -s0 -c {cap_count} -w {pcap_file_name}"
        
        await self.run_shell_cmd(cmd=pcap_cmd)

        



