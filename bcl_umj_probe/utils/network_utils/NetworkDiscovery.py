import time
from scapy.all import *
from scapy import *
from scapy.tools import *
from scapy.layers.dhcp import *
from scapy.layers.inet import * 
from scapy.layers.l2 import *
from scapy.utils import mac2str
import pyshark
import manuf
from utils.network_utils.base.Network import Network
from typing import Callable

class NetworkDiscovery(Network):
    def __init__(self):
        super().__init__()
        self.vendor_lookup = manuf.MacParser()
        self.discovery_action_map: dict[str, Callable[[dict], object]] = {
            "arp" : self.dscv_arp,
            "tcp" : self.dscv_tcp,
            "udp" : self.dscv_udp,
        }
        self.host_scan_action_map: dict[str, Callable[[dict], object]] = {
            "ack" : self.scan_ack,
            "ip" : self.scan_ip,
            "xmas" : self.scan_xmas,
        }

    def scapy_scan(self, action: str, params: dict):
        """
        Scapy scan manager

        Returns:
            results of host port discovery
        """

        handler = self.host_scan_action_map.get(action)
        if handler and params:
            ans, unans = handler(**params)

        return None if not isinstance(ans, SndRcvList) and not isinstance(unans, PacketList) else ans, unans

    def scapy_discovery(self, action: str, params: dict):
        """
        Scapy discovery manager

        Returns:
            devices (list): list of discovered hosts
        """

        handler = self.discovery_action_map.get(action)
        if handler and params:
            result = handler(**params)

        if not isinstance(result, SndRcvList):
            return None    

        devices = []
        for sent, received in result:
            received.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
            
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": self.vendor_lookup.get_manuf(received.hwsrc) or "Unknown"
            })
            
        return devices

    def pyshark_discovery(self, interface):
        cap = pyshark.LiveCapture(interface=interface, only_summaries=True)
        cap.sniff(timeout=10)
        devices = set()
        for pkt in cap:
            try:
                if "eth.src" in pkt.info or "eth.dst" in pkt.info:
                    devices.add(pkt.info.split()[0])
            except:
                continue
        return list(devices)

    def discover_devices(self, iface: str, action: str, params: dict):
        interface = iface
        discovery_results={}

        scapy_devices = self.scapy_discovery(action=action, params=params)
        if isinstance(scapy_devices, list):
        
            pyshark_macs = self.pyshark_discovery(interface)

            combined = {d['mac']: d for d in scapy_devices}
            for mac in pyshark_macs:
                if mac not in combined:
                    combined[mac] = {
                        "ip": "unknown",
                        "mac": mac,
                        "vendor": self.vendor_lookup.get_manuf(mac) or "Unknown"
                    }

            timestamp = int(time.time())
            for d in combined.values():
                key = f"device:scan:{d['mac']}"
                d['timestamp'] = timestamp
                discovery_results[key] = d

            return discovery_results if discovery_results else 2
        else: 
            return None
    
    def scan_ack(self, target: str, ports: list):
        """
        Discover unfiltered ports on target host

        Args:
            target (str): host IP or FQDN to scan

            ports (list): ports to scan for discovery.

        Returns:
            ans, unans (list) : list of filtered and unfiltered ports on target host
        """      
        unfiltered = []
        filtered = []
        ans, unans = sr(IP(dst=target)/TCP(dport=ports,flags="A", options=[('Timestamp',(0,0))]))
        # Unfiltered ports
        for s,r in ans:
            if s[TCP].dport == r[TCP].sport:
                self.logger.info(f"{s[TCP].dport} is unfiltered")
                unfiltered.append(s[TCP].dport)

        # Filtered ports
        for s in unans:
            self.logger.info(f"{s[TCP].dport} is filtered")
            filtered.append(s[TCP].dport)

        return ans, unfiltered, filtered
    
    def scan_xmas(self, target: str):
        """
        Reveals closed ports on target host

        Args:
            target (str): host IP or FQDN to scan

        Returns:
            ans, unans (list) : list of closed ports on target host
        """
        ans, unans = sr(IP(dst=target)/TCP(dport=666,flags="FPU", options=[('Timestamp',(0,0))]) )
        
        return ans
    
    def scan_ip(self, target: str):
        """
        Enumerate supported protocols on target host

        Args:
            target (str): target host to scan

        Returns:
            ans, unans (list): list of sent/received packets answered and unanswered packets
        """
        ans, unans = sr(IP(dst=target,proto=(0,255))/"SCAPY",retry=2)

        return ans
    
    def dscv_arp(self, interface: str, subnet_cidr: str):
        """
        Subnet wide host discovery using ARP

        Args:
            interface (str): iface to scna from

            subnet_cidr (str): subnet/cidr to scan

        Returns:
            devices (list): list of discovered hosts
        """
        arp = ARP(pdst=subnet_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        #result, packet_list = srp(packet, timeout=3, iface=interface, verbose=0)[0]
        ans, packet_list = srp(packet, timeout=3, iface=interface, verbose=0)
        result = ans.make_table(lambda x:(x[Ether].src, x[ARP].psrc))
        self.logger.info(ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") ))

        return ans
         
    def dscv_tcp(self, target: str, port=80):
        """
        Subnet wide host discovery using TCP SYN ping when ICMP ping is blocked.

        Args:
            target (str): target subnet to scan

            ports (int): port to scan for discovery. default 80

        Returns:
            ans (list): list of answered packets
        """
    
        ans, packet_list = sr( IP(dst=target)/TCP(dport=port,flags="S", options=[('Timestamp',(0,0))]) )
        result = ans.make_table(lambda x:(x[IP].src))
        self.logger.info(ans.summary( lambda s,r : r.sprintf("%IP.src% is alive") ))

        return ans
    
    def dscv_udp(self, target: str):
        """
        Host discovery using UDP ping in cases where all other discovery attempts fail. 
        Returns ICMP port unreachable on live hosts.

        Args:
            target (str): target subnet to scan

        Returns:
            ans (list): list of sent/received answered packets
        """
        ans, packet_list = sr(IP(dst=target)/UDP(dport=0))
        result = ans.make_table(lambda x:(x[IP].src))
        self.logger.info(ans.summary( lambda s,r : r.sprintf("%IP.src% is alive") ))

        return ans
    
    def dscv_dhcp(self, iface: str):
        """
        Identify all dhcp servers within the given vlan assigned to the specified interface

        Args:
            target (str): target subnet to scan

        Returns:
            ans (list): list of sent/received answered packets
        """

        conf.checkIPaddr = False
        self.logger.info(conf.ifaces)
        fam,hw = get_if_hwaddr(conf.iface)
        dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=iface)/DHCP(options=[("message-type","discover"),"end"])
        ans, unans = srp(dhcp_discover, multi=True, timeout=10)
        discovered_dhcp=[]
        # Return MAC and IP of discovered DHCP servers
        for p in ans: 
            discovered_dhcp.append((p[1][Ether].src, p[1][IP].src))

        return discovered_dhcp if discovered_dhcp is not [] else None
    
