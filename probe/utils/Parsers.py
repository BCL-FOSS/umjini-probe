import logging
import re

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

class Parsers:
    def __init__(self):
        pass
    
    def parse_traceroute_output(self, output: str, trace_type: str) -> list:
        """Parse traceroute output into structured hop data"""
        hops = []
        lines = output.strip().split('\n')
    
        for line in lines:
            if not line.strip() or 'traceroute' in line.lower():
                continue
            
            # Basic parsing - adjust regex based on actual output format
            import re
            
            # Match hop number, IP, and timing
            match = re.search(r'(\d+)\s+(\S+)\s+\(([^)]+)\)\s+([\d.]+)\s*ms', line)
            if match:
                hop_num, hostname, ip, rtt = match.groups()
                hops.append({
                    "hop": int(hop_num),
                    "hostname": hostname,
                    "ip": ip,
                    "rtt": float(rtt),
                    "latency": f"{rtt}ms"
                })
            else:
                # Handle timeout lines
                match_timeout = re.search(r'(\d+)\s+\*', line)
                if match_timeout:
                    hop_num = match_timeout.group(1)
                    hops.append({
                        "hop": int(hop_num),
                        "hostname": "***",
                        "ip": "***",
                        "rtt": "N/A",
                        "latency": "timeout"
                    })
        
        return hops

    def parse_iperf_output(self, iperf_json: dict) -> dict:
        """Parse iperf3 JSON output"""
        try:
            end = iperf_json.get('end', {})
            sum_sent = end.get('sum_sent', {})
            sum_received = end.get('sum_received', {})
            
            bandwidth_bps = sum_received.get('bits_per_second', 0)
            bandwidth_mbps = bandwidth_bps / 1_000_000
            
            return {
                "mode": "client",
                "client_ip": iperf_json.get('start', {}).get('connecting_to', {}).get('host'),
                "server_ip": iperf_json.get('start', {}).get('connecting_to', {}).get('host'),
                "client_port": iperf_json.get('start', {}).get('connecting_to', {}).get('port'),
                "server_port": iperf_json.get('start', {}).get('connecting_to', {}).get('port'),
                "bandwidth": f"{bandwidth_mbps:.2f} Mbps",
                "jitter": f"{sum_received.get('jitter_ms', 0):.2f} ms",
                "packet_loss": f"{sum_received.get('lost_percent', 0):.2f}%",
                "duration": sum_sent.get('seconds', 0)
            }
        except Exception as e:
            logger.error(f"Error parsing iperf output: {e}")
            return {
                "mode": "client",
                "bandwidth": "Error",
                "jitter": "N/A",
                "packet_loss": "N/A"
            }

    def parse_pcap_summary(self, tcpdump_output: str) -> list:
        """Parse tcpdump output into packet list"""
        packets = []
        lines = tcpdump_output.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            
            # Example: 12:34:56.789012 IP 192.168.1.1.12345 > 192.168.1.2.80: Flags [S], length 60
            match = re.search(r'(\d+:\d+:\d+\.\d+)\s+(\w+)\s+(\S+)\s+>\s+(\S+).*length\s+(\d+)', line)
            if match:
                timestamp, protocol, src, dst, size = match.groups()
                
                # Extract IPs from addresses
                src_ip = src.split('.')[0:4]
                dst_ip = dst.split('.')[0:4]
                src_ip_str = '.'.join(src_ip) if len(src_ip) == 4 else src
                dst_ip_str = '.'.join(dst_ip) if len(dst_ip) == 4 else dst
                
                packets.append({
                    "timestamp": timestamp,
                    "protocol": protocol,
                    "src_ip": src_ip_str,
                    "dst_ip": dst_ip_str,
                    "size": int(size)
                })
        
        return packets[:100]  # Limit to first 100 packets for visualization

    def parse_nmap_json(self, nmapData: dict):
        """Parse nmap JSON output into device dictionary"""
        devices = {}
        
        # Handle different nmap JSON structures
        hosts = nmapData.get('nmaprun', {}).get('host', [])
        if not isinstance(hosts, list):
            hosts = [hosts] if hosts else []
        
        for index, host in enumerate(hosts):
            # Skip hosts that are down
            status = host.get('status', {})
            if isinstance(status, dict) and status.get('@state') != 'up':
                continue
            
            # Extract addresses
            addresses = host.get('address', [])
            if not isinstance(addresses, list):
                addresses = [addresses] if addresses else []
            
            ipv4_addr = next((addr for addr in addresses if addr.get('@addrtype') == 'ipv4'), None)
            mac_addr = next((addr for addr in addresses if addr.get('@addrtype') == 'mac'), None)
            
            ip = ipv4_addr.get('@addr', f'unknown-{index}') if ipv4_addr else f'unknown-{index}'
            mac = mac_addr.get('@addr', f'{ip}-mac') if mac_addr else f'{ip}-mac'
            vendor = mac_addr.get('@vendor', 'Unknown') if mac_addr else 'Unknown'
            
            # Extract ports
            ports_data = host.get('ports', {}).get('port', [])
            if not isinstance(ports_data, list):
                ports_data = [ports_data] if ports_data else []
            
            open_ports = [
                port.get('@portid') 
                for port in ports_data 
                if port.get('state', {}).get('@state') == 'open'
            ]
            
            # Determine device role
            role = self.determine_device_role(ports_data, host.get('os'), ', '.join(open_ports))
            
            # Extract hostname
            hostnames = host.get('hostnames', {}).get('hostname', {})
            if isinstance(hostnames, list):
                hostname = hostnames[0].get('@name', ip) if hostnames else ip
            else:
                hostname = hostnames.get('@name', ip) if hostnames else ip
            
            # Extract OS information
            os_matches = host.get('os', {}).get('osmatch', [])
            if not isinstance(os_matches, list):
                os_matches = [os_matches] if os_matches else []
            
            os_match = os_matches[0] if os_matches else {}
            os_name = os_match.get('@name', 'Unknown OS')
            os_accuracy = os_match.get('@accuracy', 'N/A')
            
            devices[mac] = {
                'mac': mac,
                'ip': ip,
                'vendor': vendor,
                'role': role,
                'open_ports': ', '.join(open_ports) if open_ports else 'none',
                'hostname': hostname,
                'os': os_name,
                'os_accuracy': os_accuracy,
                'services': self.extract_services(ports_data)
            }
        
        return devices

    def determine_device_role(self, ports, os_info, open_ports_str):
        """Determine device role based on open ports and OS"""
        if not isinstance(ports, list):
            ports = [ports] if ports else []
        
        port_numbers = [
            int(port.get('@portid', 0))
            for port in ports
            if port.get('state', {}).get('@state') == 'open'
        ]
        
        # Firewall detection
        if 443 in port_numbers and 22 in port_numbers and len(port_numbers) < 10:
            return 'firewall'
        
        # Switch detection
        if 161 in port_numbers or 23 in port_numbers:
            return 'switch'
        
        # Server detection
        server_ports = [80, 443, 22, 21, 3306, 5432, 1433, 3389, 8080, 8443]
        if any(p in server_ports for p in port_numbers) and len(port_numbers) >= 3:
            return 'server'
        
        # Endpoint detection
        if len(port_numbers) <= 5:
            return 'endpoint'
        
        return 'unknown'

    def extract_services(self, ports):
        """Extract service information from ports"""
        if not isinstance(ports, list):
            ports = [ports] if ports else []
        
        services = []
        for port in ports:
            if port.get('state', {}).get('@state') != 'open':
                continue
            
            port_id = port.get('@portid', '')
            service = port.get('service', {})
            service_name = service.get('@name', 'unknown')
            product = service.get('@product', '')
            version = service.get('@version', '')
            
            service_str = f"{port_id}/{service_name} {product} {version}".strip()
            services.append(service_str)
        
        return ', '.join(services)