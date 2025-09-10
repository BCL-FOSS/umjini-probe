import os
import platform
import subprocess
import requests
import iperf3
from iperf3 import TestResult
from utils.network_utils.base.Network import Network
from scapy.all import *
from scapy import *
from scapy.tools import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.layers import dns
from scapy.layers.dns import *

class NetworkTest(Network):
    def __init__(self):
        super().__init__()

    def start_iperf(self, mode: str, remote_host: str='', server_port=7969, duration=30, verbose=True, reverse=False, udp=False):
        match mode:
            case 'cl':
                if udp is False:
                    protocol='tcp'
                else:
                    protocol = 'udp'
                client = iperf3.Client()
                client.duration = duration
                client.server_hostname = remote_host
                client.protocol = protocol
                client.port = server_port
                client.blksize = 1234
                client.num_streams = 10
                client.zerocopy = True
                client.verbose = verbose
                client.reverse = reverse
                result = client.run()
              
            case 'sr':
                server = iperf3.Server()
                server.bind_address = '0.0.0.0'
                server.port = server_port
                server.verbose = True
                server.json_output=True
                #server.run()
                run = True
                while run:
                   result = server.run()
                   if isinstance(result, TestResult):
                       run = False
                
            case _:
                 pass
            
        self.logger.info('')
        self.logger.info('Test completed:')
        self.logger.info('  started at         {0}'.format(result.time))
        self.logger.info('  bytes transmitted  {0}'.format(result.bytes))
        self.logger.info('  jitter (ms)        {0}'.format(result.jitter_ms))
        self.logger.info('  avg cpu load       {0}%\n'.format(result.local_cpu_total))
        self.logger.info('Average transmitted data in all sorts of networky formats:')
        self.logger.info('  bits per second      (bps)   {0}'.format(result.bps))
        self.logger.info('  Kilobits per second  (kbps)  {0}'.format(result.kbps))
        self.logger.info('  Megabits per second  (Mbps)  {0}'.format(result.Mbps))
        self.logger.info('  KiloBytes per second (kB/s)  {0}'.format(result.kB_s))
        self.logger.info('  MegaBytes per second (MB/s)  {0}'.format(result.MB_s))

        scan_result = {"test_start": result.time,
                        "bytes_trans": result.bytes,
                        "jitter": result.jitter_ms,
                        "avg_cpu_load": result.local_cpu_total,
                        "bps": result.bps,
                        "kbitps": result.kbps,
                        "mbitps": result.Mbps,
                        "kbytps": result.kB_s,
                        "mbytps": result.MB_s}
        
        return scan_result

    def traceroute_syn(self, dest: str, port=80):
        """
        SYN traceroute

        Args:
            dest (str): host to trace route to

            port (int): service port to test (default HTTP)

        Returns:
            router_list (str): list of routers identified during trace
        """
        ans, unans = sr(IP(dst=dest,ttl=(1,10))/TCP(dport=port,flags="S", options=[('Timestamp',(0,0))]))
        #ans.summary(lambda s,r: r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}"))

        self.logger.info(ans.make_table(lambda s,r: (s.dst, s.ttl, r.src)))
        
        return ans
    
    def traceroute_udp(self, target: str, query: str ='google.com'):
        """
        Traces UDP applications. Tracerouting an UDP application like we do with TCP is not reliable, because there’s no handshake.
        We need to give an applicative payload (DNS, ISAKMP, NTP, etc.) to deserve an answer

        Args:
            dest (str): host to trace route to

            query (str): domain for query. defaults to google.com

        Returns:
            router_list (str): list of routers identified during trace
        """

        #res, unans = sr(IP(dst=target, ttl=(1,20)) /UDP()/app)

        ans, unans = sr(IP(dst=target, ttl=(1,20))/UDP()/DNS(qd=DNSQR(qname=query)))

        self.logger.info(ans.make_table(lambda s,r: (s.dst, s.ttl, r.src)))
        return ans
    
    def traceroute_dns(self, target: list, query: str = 'google.com'):
        """
        Performs DNS traceroute

        Args:
            target (str): host to trace route to

            query (str): domain for query. defaults to google.com

        Returns:
            router_list (str): list of routers identified during trace
        """
        ans, unans = traceroute(target=target,l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname=query)))
     
        self.logger.info(ans.make_lined_table(lambda s,r: (s.dst, r.src)))
        return ans


       
