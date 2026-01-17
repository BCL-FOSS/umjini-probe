from base.Network import Network

class NetworkDiscovery(Network):
    def __init__(self):
        super().__init__()

    def set_interface(self, iface: str):
        self.interface = iface

    async def arp_scan(self, subnet: str):
        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -sn -PR {subnet}")

        return code, output, error
    
    async def device_detection(self, subnet: str, noise: False):
        if noise is True:
            code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -sS -O -sV {subnet}")

        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -sS -sV --version-light {subnet}")

        return code, output, error
    
    async def snmp_scans(self, subnet: str, type: str):
        match type:
            case 'snmp_opn':
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -p 161 -sU {subnet}")
            case 'snmp_info':
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -p 161 -sU --script snmp-info {subnet}")
            case 'snmp_enum': 
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -p 161 -sU --script snmp-sysdescr,snmp-interfaces {subnet}")
                
        return code, output, error
    
    async def device_fingerprint(self, ip: str):
        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -O --osscan-guess {ip}")

        return code, output, error
    
    async def traceroute_scan(self, subnet: str):
        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} --traceroute {subnet}")

        return code, output, error
    
    async def switch_detection(self, subnet: str, type: str):
        match type:
            case 'ports':
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -p 22,23,80,443,161,830 {subnet}")
            case 'mac-oui':
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -sn {subnet} --osscan-limit")

        return code, output, error
    
    async def wirelss_ap_detection(self, subnet: str, type: str):
        match type:
            case 'os':
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -sS -O -p 22,80,443,8080,8443,8880 {subnet}")
            case 'web-gui':
                code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -p 80,443 --script http-title {subnet}")

        return code, output, error
    
    async def full_network_scan(self, subnet: str):
        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -A {subnet}")

        return code, output, error
    
    async def device_classification(self, subnet: str):
        code, output, error = await self.run_shell_cmd(cmd=f"nmap -e {self.interface} -sn {subnet} | grep -E 'MAC Address|Nmap scan report'")

        return code, output, error

    
    





