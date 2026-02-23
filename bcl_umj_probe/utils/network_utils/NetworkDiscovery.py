from utils.network_utils.base.Network import Network

class NetworkDiscovery(Network):
    def __init__(self):
        super().__init__()
        self.file_name = "nmap_scan.xml"
        self.interface = 'eth0'
        if self.file_name:
            self.command = f"nmap -e {self.interface} -oX {self.file_name}"
        else:
            self.command = f"nmap -e {self.interface}"
        self.command_map = {
            "arp": f"{self.command} -sn -PR",
            "dev_id": f"{self.command} -sS -sV --version-light",
            "dev_id_noise": f"{self.command} -sS -O -sV",
            "snmp": f"{self.command} -p 161 -sU",
            "dev_fngr": f"{self.command} -O --osscan-guess",
            "dev_fngr_limit": f"{self.command} -O --osscan-limit",
        }

    def set_output_file(self, file_name: str):
        self.file_name = file_name

    def set_interface(self, iface: str):
        self.interface = iface

    async def arp_scan(self, subnet: str):
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command} -sn -PR {subnet}")
        return code, output, error
    
    async def device_identification_scan(self, subnet: str, noise: bool = False, export_file_name: str = None):
        if noise is True:
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get("dev_id_noise")} {subnet}")
        else:
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get("dev_id")} {subnet}")
        return code, output, error
    
    async def snmp_scans(self, subnet: str, type: str, export_file_name: str, scripts: str = 'snmp-sysdescr,snmp-interfaces'):
        match type:
            case 'snmp_opn':
                code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map['snmp']} {subnet} -oX {export_file_name}")
            case 'snmp_enum': 
                code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map['snmp']} --script={scripts} {subnet} -oX {export_file_name}")
            case 'snmp_all':
                code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map['snmp']} -sV -sC {subnet} -oX {export_file_name}")
                
        return code, output, error
    
    async def device_fingerprint_scan(self, subnet: str, limit: bool = True):
        if limit is False:
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get("dev_fngr")} {subnet}")
        else:
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get("dev_fngr_limit")} {subnet}")
        return code, output, error
    
    async def port_scan(self, subnet: str, ports: str='22,23,80,443,161,830'):
     
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command} -p {ports} {subnet}")

        return code, output, error
    
    async def custom_scan(self, subnet: str, options: str):
        
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command} {options} {subnet}")

        return code, output, error
    
    async def full_network_scan(self, subnet: str):
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command} -A {subnet}")

        return code, output, error

    
    





