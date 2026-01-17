import socket
import psutil
import subprocess
import platform
import re
import shutil
import fcntl
import struct
from utils.network_utils.base.Network import Network
import uuid
import dns.resolver
import dns.reversename
import ipaddress


class ProbeInfo(Network):
    def __init__(self):
        super().__init__()

    def gen_probe_register_data(self):
        id=self.gen_id()
        hostname=socket.gethostname()
        probe_id=f"prb-{hostname}-{id}"

        if probe_id and hostname:
            return probe_id, hostname
        
    def read_txt_file(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                data = file.read()
            return data
        except FileNotFoundError:
            return f"File not found: {filepath}"
        except Exception as e:
            return f"An error occurred: {str(e)}"

    def gen_id(self):
        id = uuid.uuid4()
        if id:
            return str(id)
        else:
            return self.logger.info("Probe ID Gen Failed")  
    
    def collect_local_stats(self, id: str, hostname: str):
        stat_data = {}
        stat_data["prb_id"] = id
        stat_data["hstnm"] = hostname

        self.logger.info("\n📍 Local System Stats")
        stat_data["sys"] = f"{platform.system()} {platform.release()}"
        stat_data["cpu"] = f"{psutil.cpu_percent()}%"
        mem = psutil.virtual_memory()
        stat_data["mem"] = f"{mem.used / 1024**2:.2f} MB / {mem.total / 1024**2:.2f} MB"
        disk = psutil.disk_usage('/')
        stat_data["dsk"] = f"{disk.used / 1024**3:.2f} GB / {disk.total / 1024**3:.2f} GB"
        uptime = subprocess.getoutput("uptime -p")
        stat_data["upt"] = uptime
        stat_data["ifcs"] = {}

        self.logger.info("\n🔌 Interface Statistics:")
        for iface, addrs in psutil.net_if_addrs().items():
            if iface in ("lo", "lo0"):
                continue

            stats = psutil.net_if_stats().get(iface)
            io = psutil.net_io_counters(pernic=True).get(iface)

            stat_data["ifcs"][iface] = {}

            if stats:
                stat_data["ifcs"][iface]["dta"] = {
                    "isup": stats.isup,
                    "duplex": stats.duplex,
                    "speed": stats.speed,
                    "mtu": stats.mtu,
                }

            if io:
                stat_data["ifcs"][iface]["bndwth_io"] = (
                    f"Sent: {io.bytes_sent / 1024:.2f} KB | "
                    f"Recv: {io.bytes_recv / 1024:.2f} KB"
                )
                stat_data["ifcs"][iface]["pckt_io"] = (
                    f"Sent Packets: {io.packets_sent} | "
                    f"Recv Packets: {io.packets_recv}"
                )

            self.logger.info(f"Interface: {iface}")
            if stats:
                self.logger.info(f"  Speed: {stats.speed} Mbps")
                self.logger.info(f"  Status: {'UP' if stats.isup else 'DOWN'}")
            if io:
                self.logger.info(
                    f"  Sent: {io.bytes_sent / 1024:.2f} KB | "
                    f"Recv: {io.bytes_recv / 1024:.2f} KB"
                )

        return stat_data if stat_data else None

    def get_interface_subnet(swlf, interface: str):
        addrs = psutil.net_if_addrs().get(interface, [])

        for addr in addrs:
            if addr.family.name == 'AF_INET':
                ip = addr.address
                netmask = addr.netmask

                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)

                return {
                    "interface": interface,
                    "ip": ip,
                    "netmask": netmask,
                    "cidr": network.prefixlen,
                    "subnet": str(network.network_address),
                    "network": str(network)
                }

        return None

    def get_default_interface_subnet():
        gws = psutil.net_if_stats()
        for iface, stats in gws.items():
            if stats.isup:
                addrs = psutil.net_if_addrs().get(iface, [])
                for addr in addrs:
                    if addr.family.name == 'AF_INET':
                        network = ipaddress.IPv4Network(
                            f"{addr.address}/{addr.netmask}",
                            strict=False
                        )
                        return iface, network
        return None

        
    def get_url_from_ip(self, ip_address: str, port: int | None = 8000, timeout: int = 2) -> str:
        host = ip_address

        fqdn = socket.getfqdn(ip_address)
        if fqdn and fqdn != ip_address:
            host = fqdn
     
        if host == ip_address:
            rev_name = dns.reversename.from_address(ip_address)
            answers = dns.resolver.resolve(rev_name, "PTR")
            host = str(answers[0]).rstrip(".")

        scheme = "http"
        test_ports = [443, 80] if port is None else [port]

        for test_port in test_ports:
            with socket.create_connection((ip_address, test_port), timeout=timeout):
                if test_port == 443:
                    scheme = "https"
                else:
                    scheme = "http"
                port = test_port
                break
            
        if port in (80, 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def get_interface_ip(self, interface: str) -> str:
        """
        Retrieves IP address assigned to a specific interface

        Args:
            interface (str): Interface for IP discovery.

        Returns:
            ip (str): IP address of specified interface
        """

        match self.system:
            case 'Linux':
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ip = socket.inet_ntoa(
                        fcntl.ioctl(
                            sock.fileno(),
                            0x8915,  # SIOCGIFADDR
                            struct.pack('256s', interface.encode('utf-8')[:15])
                        )[20:24]
                    )

                if not ip:
                    output = subprocess.check_output(["ip", "addr", "show", interface], text=True)
                    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
                    if match:
                        return match.group(1)
                    else:
                        return 2
                else:
                    return ip
                
            case 'FreeBSD':
                output = subprocess.check_output(["ifconfig", interface], text=True)
                match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
                if match:
                    return match.group(1)
                else:
                    return 2
            case _:
                self.logger.info('OS not supported')
                return 2       

    def get_default_interface(self) -> str:
        """
        Retrieves the default interface of the probe host

        Returns:
            ip (str): IP address of specified interface
        """

        match self.system:
            case 'Linux':
                output = subprocess.check_output(["ip", "route", "get", "1.1.1.1"], text=True)
                match = re.search(r"dev (\w+)", output)
                if match:
                    return match.group(1)
                else:
                    return 2
            case 'FreeBSD':
                # Prefer route -n get default
                output = subprocess.check_output(["route", "-n", "get", "default"], text=True)
                if output:
                    match = re.search(r"interface: (\w+)", output)
                    if match:
                            return match.group(1)
                else:
                    output = subprocess.check_output(["netstat", "-rn"], text=True)
                    if output:
                        for line in output.splitlines():
                            if line.startswith("default") or line.startswith("0.0.0.0"):
                                parts = line.split()
                                if len(parts) >= 7:
                                    return parts[-1]  # Interface name    
                    else:
                        return 2       
            case _:
                self.logger.info('OS not supported')
                return 2
              
        
    def get_ifaces(self):
        """
        Retrieves all available interfaces of the probe host

        Returns:
            interfaces (list): List of all identified host interfaces 
        """

        interfaces = []

        match self.system:
            case 'linux':
                    if shutil.which('ip'):
                        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, check=True)
                        if result:
                            for line in result.stdout.splitlines():
                                if line and line[0].isdigit():
                                    iface = line.split(':')[1].strip().split('@')[0]  # Remove @altname if present
                                    if iface != 'lo':  # exclude loopback
                                        interfaces.append(iface)
                            return interfaces
                        else:
                            return 2
            case 'freebsd':
                    if shutil.which('ifconfig'):
                        result = subprocess.run(['ifconfig'], capture_output=True, text=True, check=True)
                        if result:
                            # Match interface names at start of lines like: `em0: flags=...`
                            for line in result.stdout.splitlines():
                                match = re.match(r'^([a-zA-Z0-9]+):', line)
                                if match:
                                    iface = match.group(1)
                                    if iface != 'lo0':  # optionally exclude loopback
                                        interfaces.append(iface)
                            return interfaces
                        else:
                            return 2   
            case _:
                self.logger.info('OS not supported')
                return 2

    def get_processes_by_names(self, process_names: list):
        """
        Retrieves all running processes, or processes according to list of specified names.

        Args:
            process_names (list): List of processes to find

        Returns:
            matching_processes (list): List of all or identified processes
        """
        matching_processes = []
        
        try:
            
            if process_names:

                lower_case_names = [name.lower() for name in process_names]
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        
                            proc_name = proc.info['name']
                            if proc_name and proc_name.lower() in lower_case_names:
                                matching_processes.append({
                                    'pid': proc.info['pid'],
                                    'name': proc_name,
                                    'cmdline': proc.info['cmdline']
                                })
                return matching_processes
            
            else:
               
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        
                    proc_name = proc.info['name']
                        
                    matching_processes.append({
                                    'pid': proc.info['pid'],
                                    'name': proc_name,
                                    'cmdline': proc.info['cmdline']
                                })
                return matching_processes
                        
        except Exception as e:
                self.logger.error(f"Error retrieving processes: {e}")
                return 2
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


    def open_listening_ports(self):
        """
        Retrieves all listening ports on supported linux and freebsd firewalls

        Returns:
            ports (list): List of all current open ports on the probe's host firewall
        """

        ports = set()

        match self.system:
            case 'freebsd':
                self.logger.info("Detected FreeBSD...")
                if self.is_pf_enabled():
                    self.logger.info("PF is enabled. Parsing pf rules...")
                    result = subprocess.run(['pfctl', '-sr'], capture_output=True, text=True, check=True)
                    ports.update(self.parse_pf(result.stdout))
                elif self.is_ipfw_enabled():
                    self.logger.info("IPFW is enabled. Parsing ipfw rules...")
                    result = subprocess.run(['ipfw', 'list'], capture_output=True, text=True, check=True)
                    ports.update(self.parse_ipfw(result.stdout))
                else:
                    self.logger.info("No known firewall (pf/ipfw) enabled on FreeBSD.")
            case 'linux':
                os_release = subprocess.run(['cat', '/etc/os-release'], capture_output=True, text=True).stdout.lower()

                if 'debian' in os_release or 'ubuntu' in os_release:
                    self.logger.info("Detected Debian-based Linux...")
                    if shutil.which('iptables'):
                        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, check=True)
                        ports.update(self.parse_iptables(result.stdout))
                    if shutil.which('nft'):
                        result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, check=True)
                        ports.update(self.parse_nftables(result.stdout))

                elif 'rhel' in os_release or 'centos' in os_release or 'fedora' in os_release:
                    self.logger.info("Detected RHEL-based Linux...")
                    if shutil.which('iptables'):
                        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, check=True)
                        ports.update(self.parse_iptables(result.stdout))
                    if shutil.which('firewall-cmd'):
                        try:
                            result = subprocess.run(['firewall-cmd', '--list-ports'], capture_output=True, text=True, check=True)
                            ports.update(self.parse_firewalld(result.stdout))
                        except subprocess.CalledProcessError:
                            self.logger.info("firewalld not running or not installed.")
                    if shutil.which('nft'):
                        result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, check=True)
                        ports.update(self.parse_nftables(result.stdout))
                else:
                    self.logger.info("Unsupported Linux distro.")
            case _:
                self.logger.info('OS not supported')
                return 2

        for port in sorted(ports):
                self.logger.info(f"Open port {port} is ALLOWED")

        return sorted(ports) if ports else 2
    
    def get_iface_ips(self):
        """
        Retrieves all interfaces and assosciated IP addresses of the probe host. Useful when using probe in monitor mode.

        Returns:
            iface_data (dict): Dict of all ifaces and assosciated IPs
        """
        ifaces_data = {}
        all_ifaces = self.get_ifaces()

        for iface in all_ifaces:
            iface_ip = self.get_interface_ip(interface=iface)
            ifaces_data[iface] = iface_ip

        return ifaces_data if ifaces_data.items() else None
    
    def get_probe_data(self):
        """
        Returns all relevant probe host system data. Useful when using probe in monitor mode.

        Returns:
            iface_data (dict): Dict of all host system data
        """
        id, hstnm = self.gen_probe_register_data()
        data = self.collect_local_stats(id='', hostname=hstnm)

        return data if data.items() else None
       
    # Port Retrieval Helper Functions

    def parse_iptables(self, output):
        ports = set()
        for line in output.splitlines():
            match = re.search(r'dpt:(\d+)', line)
            if match:
                ports.add(int(match.group(1)))
        return ports

    def parse_pf(self, output):
        ports = set()
        for line in output.splitlines():
            match = re.search(r'port\s*=\s*(\d+)', line)
            if match:
                ports.add(int(match.group(1)))
            else:
                match = re.search(r'port\s+(\d+)', line)
                if match:
                    ports.add(int(match.group(1)))
        return ports

    def parse_ipfw(self, output):
        ports = set()
        for line in output.splitlines():
            match = re.search(r'(?i)tcp\s+from.*to.*(\d{1,5})', line)
            if match:
                ports.add(int(match.group(1)))
        return ports

    def parse_firewalld(self, output):
        ports = set()
        for port_proto in output.strip().split():
            if '/' in port_proto:
                port, _ = port_proto.split('/')
                ports.add(int(port))
        return ports

    def parse_nftables(self, output):
        ports = set()
        for line in output.splitlines():
            match = re.search(r'(?i)dport\s+(\d+)', line)
            if match:
                ports.add(int(match.group(1)))
        return ports

    def is_pf_enabled(self):
        try:
            result = subprocess.run(['sysctl', 'net.pf.enabled'], capture_output=True, text=True)
            return 'net.pf.enabled: 1' in result.stdout
        except:
            return False

    def is_ipfw_enabled(self):
        try:
            result = subprocess.run(['sysctl', 'net.inet.ip.fw.enable'], capture_output=True, text=True)
            return 'net.inet.ip.fw.enable: 1' in result.stdout
        except:
            return False
    

    


            
       

        
        
        
    
        
         
