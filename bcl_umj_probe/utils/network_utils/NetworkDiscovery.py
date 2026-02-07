from utils.network_utils.base.Network import Network

class NetworkDiscovery(Network):
    def __init__(self):
        super().__init__()

    def set_interface(self, iface: str):
        self.interface = iface

    async def arp_scan(self, subnet: str, export_file_name: str):
        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -sn -PR {subnet} -oX {export_file_name}")

        return code, output, error
    
    async def device_identification_scan(self, subnet: str, noise: False, export_file_name: str = None):
        if noise is True:
            code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -sS -O -sV {subnet} -oX {export_file_name}")
        else:
            code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -sS -sV --version-light {subnet} -oX {export_file_name}")
        return code, output, error
    
    async def snmp_scans(self, subnet: str, type: str, export_file_name: str, scripts: str = 'snmp-sysdescr,snmp-interfaces'):
        match type:
            case 'snmp_opn':
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -p 161 -sU {subnet} -oX {export_file_name}")
            case 'snmp_enum': 
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -p 161 -sU --script={scripts} {subnet} -oX {export_file_name}")
            case 'snmp_all':
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -p 161 -sU -sV -sC {subnet} -oX {export_file_name}")
                
        return code, output, error
    
    async def device_fingerprint_scan(self, subnet: str, export_file_name: str, limit: bool = True):
        if limit is False:
            code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -O --osscan-guess {subnet} -oX {export_file_name}")
        else:
            code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -O --osscan-limit {subnet} -oX {export_file_name}")
        return code, output, error
    
    async def port_scan(self, subnet: str, export_file_name: str, ports: str='22,23,80,443,161,830'):
     
        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -p {ports} {subnet} -oX {export_file_name}")

        return code, output, error
    
    async def custom_scan(self, subnet: str, options: str, export_file_name: str):
        
        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} {options} {subnet} -oX {export_file_name}")

        return code, output, error
    
    async def full_network_scan(self, subnet: str, export_file_name: str):
        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -A {subnet} -oX {export_file_name}")

        return code, output, error

    
    





