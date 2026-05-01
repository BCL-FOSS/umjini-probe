from utils.network_utils.base.Network import Network

class NetworkDiscovery(Network):
    def __init__(self):
        super().__init__()
        self.file_name = None
        self.interface = None
        self.community_string = None
        self.command = f"nmap --noninteractive --disable-arp-ping"

    def set_command(self):
        if self.file_name is not None:
            self.command += f" -oX {self.file_name}"

        if self.community_string is not None:
            self.command += f" --script-args snmp.community={self.community_string}"

        if self.interface is not None:
            self.command += f" -e {self.interface}"
    
        self.command_map = {
            "services": f"{self.command} -sS -sV -T3 -sn",
            "snmp": f"{self.command} -p 161 -sU -T3 -sn",
            "os": f"{self.command} -O --osscan-guess -sn -T3",
            "map": f"{self.command} -sn -T2 -O --osscan-limit -sV --version-light --discovery-ignore-rst",
            "vulner": f"{self.command} -sV --script vulners -Pn -sn -T3",
        }
    
    def set_community_string(self, community_str: str):
        self.community_string = community_str

    def set_output_file(self, file_name: str):
        self.file_name = file_name

    def set_interface(self, iface: str):
        self.interface = iface

    def get_interface(self):
        return self.interface

    async def vulnerabilities(self, target: str, min_score: str = None):
        cmd = f"{self.command_map.get('vulner')} {target}"
        if min_score:
            cmd += f" --script-args vulners.mincvss={min_score}"
        code, output, error = await self.run_shell_cmd(cmd=cmd)
        return code, output, error
    
    async def snmp(self, target: str, scripts: str = 'snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat'):
        if scripts == 'all':
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('snmp')} -sV -sC {target}")
        else:
            code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('snmp')} --script={scripts} {target}")
        return code, output, error
    
    async def operating_system(self, target: str):
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('os')} {target}")
        return code, output, error
    
    async def services(self, target: str):
     
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('services')} {target}")

        return code, output, error
    
    async def custom(self, target: str, options: str):
        
        code, output, error = await self.run_shell_cmd(cmd=f"nmap {options} {target}")

        return code, output, error
    
    async def mapper(self, target: str, syn_ports: str = '22,23,80,443,830,3389', ack_ports: str = '80,443'):
        code, output, error = await self.run_shell_cmd(cmd=f"{self.command_map.get('map')} -PS{syn_ports} -PA{ack_ports} -PU {target}")

        return code, output, error

    
    





