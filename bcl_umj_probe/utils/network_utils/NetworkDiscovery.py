from utils.network_utils.base.Network import Network
from datetime import datetime, timezone

class NetworkDiscovery(Network):
    def __init__(self):
        super().__init__()
        self.file_name = 'nmap_scan.xml'
        self.interface = 'eth0'
        self.community_string = 'public'
        self.command = f"nmap -e {self.interface}"

    def set_command(self):
        if self.file_name is not None:
            self.command = f"nmap -e {self.interface} -oX {self.file_name}"
        else:
            self.command = f"nmap -e {self.interface}"

        if self.community_string != 'public':
            self.command += f" --script-args snmp.community={self.community_string}"

        if self.file_name != 'nmap_scan.xml':
            self.command += f" -oX {self.file_name}"

        if self.interface != 'eth0':
            self.command += f" -e {self.interface}"
        else:
            self.command += f" -e {self.interface}"
    
        self.command_map = {
            "arp": f"{self.command} -sn -PR",
            "dev_id": f"{self.command} -sS -sV --version-light",
            "dev_id_noise": f"{self.command} -sS -O -sV",
            "snmp": f"{self.command} -p 161 -sU",
            "dev_fngr": f"{self.command} -O --osscan-guess",
            "dev_fngr_limit": f"{self.command} -O --osscan-limit",
            "full_scan": f"{self.command} -A",
            "ports": f"{self.command} -p"
        }
    
    def set_community_string(self, community_str: str):
        self.community_string = community_str

    def set_output_file(self, file_name: str):
        self.file_name = file_name

    def set_interface(self, iface: str):
        self.interface = iface

    async def arp_scan(self, subnet: str):
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('arp')} -sn -PR {subnet}")
        return code, output, error
    
    async def device_identification_scan(self, subnet: str, noise: bool = False):
        if noise is True:
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('dev_id_noise')} {subnet}")
        else:
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('dev_id')} {subnet}")
        return code, output, error
    
    async def snmp_scans(self, subnet: str, type: str, scripts: str = 'snmp-sysdescr,snmp-interfaces'):
        match type:
            case 'snmp_opn':
                code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('snmp')} {subnet}")
            case 'snmp_enum': 
                code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('snmp')} --script={scripts} {subnet}")
            case 'snmp_all':
                code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('snmp')} -sV -sC {subnet}")
                
        return code, output, error
    
    async def device_fingerprint_scan(self, subnet: str, limit: bool = True):
        if limit is False:
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('dev_fngr')} {subnet}")
        else:
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('dev_fngr_limit')} {subnet}")
        return code, output, error
    
    async def port_scan(self, subnet: str, ports: str='22,23,80,443,161,830'):
     
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('ports')} {ports} {subnet}")

        return code, output, error
    
    async def custom_scan(self, subnet: str, options: str):
        
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command} {options} {subnet}")

        return code, output, error
    
    async def full_network_scan(self, subnet: str):
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('full_scan')} {subnet}")

        return code, output, error

    
    





