from fastmcp import FastMCP
from typing import Annotated
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.NetUtil import NetUtil
from utils.network_utils.NetworkSNMP import NetworkSNMP
from utils.network_utils.ProbeInfo import ProbeInfo
import logging
from fastmcp.server.auth import TokenVerifier
import redis
import logging
from fastapi import HTTPException, status
from passlib.hash import bcrypt

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

probe_utils = ProbeInfo()

r = redis.Redis(host='localhost', port=6379, decode_responses=True)
pong = r.ping()
logger.info(f"Redis ping: {pong}")

class ApiKeyVerifier(TokenVerifier):
    def __init__(self, *, header_name: str = "x-api-key"):
        super().__init__(...)
        self.header_name = header_name

    def verify(self, token: str):
        _, hostname = probe_utils.gen_probe_register_data()
        cursor, keys = r.scan(cursor=0, match=f'*{hostname}*')

        if keys:
            for redis_key in keys:
                hash_data = r.hgetall(redis_key)
                logger.info(hash_data)
                stored_api_key = hash_data.get("api_key")
                logger.info(stored_api_key)

                if not stored_api_key:
                    raise

                if bcrypt.verify(token, stored_api_key):
                    return 200
                else:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or missing API key"
                    )

auth = ApiKeyVerifier()
mcp = FastMCP(name="Network Util MCP", auth=auth)

net_discovery = NetworkDiscovery()
net_test = NetworkTest()
net_utils = NetUtil(interface='')
net_snmp = NetworkSNMP()

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

@mcp.tool
async def network_discovery(action: Annotated[str, "The type of network scan to run. The scan types are arp, tcp & udp."], iface: Annotated[str, "The network interface to run the network scan from"], subnet: Annotated[str, "The subnet/VLAN to run the network device discovery scan in"]):
    """Use for network device discovery within the specified subnet and network interface"""
    discovered_devices = await net_utils.full_discovery(action=action, interface=iface, subnet=subnet)

    return discovered_devices

@mcp.tool
def speedtest(mode: Annotated[str, "Sets the probe as either the speedtest client or server. To set as server use 'sr'. To set as the client use 'cl'."], remote_host: Annotated[str, "The server to conduct the speedtest with. Required only if the probe is set as the client."], duration: Annotated[int, "Set the duration of the speedtest. Default is set as 30 seconds."], reverse: Annotated[bool, "Toggle the direction of the speedtest. Default is set to False, which performs a speedtest from client to server"], protocol: Annotated[bool, "Set the protocol of the test. Use False to run a TCP speedtest or True to run a UDP speedtest. Only required if the probe is set as the speedtest client."]):
    """Use to perform a network speedtest"""

    if mode == 'cl':
        result = net_test.start_iperf(mode=mode, remote_host=remote_host, duration=duration, reverse=reverse, udp=protocol)
    
    if mode == 'sr':
        result = net_test.start_iperf(mode=mode)

    return result

@mcp.tool
def traceroute_syn(target: Annotated[str, "The server or endpoint to trace."], port: Annotated[int, "The TCP port (or service) to test."], ):
    """Use to trace the route from the host probe to the TCP application (or port) on the specified target."""
    routers = net_test.traceroute_syn(target=target, port=port)

    for pkt in routers:
        logger.info(pkt)

    return routers

@mcp.tool
def traceroute_dns(target: Annotated[str, "The server or endpoint to trace."], query: Annotated[str, "The domain to DNS query."], ):
    """Use to trace the route taken by the DNS query to the specified target."""
    routers = net_test.traceroute_dns(target=target, query=query)

    for pkt in routers:
        logger.info(pkt)

    return routers

@mcp.tool
def traceroute_udp(target: Annotated[str, "The server or endpoint to trace."], query: Annotated[str, "The domain to run the DNS query trace on."], ):
    """Use to trace the route from the host probe to the UDP application specified in the target. """
    routers = net_test.traceroute_udp(target=target, query=query)

    for pkt in routers:
        logger.info(pkt)

    return routers
    


