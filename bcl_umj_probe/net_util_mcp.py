from fastmcp import FastMCP
from init_app import (
    logger,
    net_test,
    net_discovery,
    net_snmp,
    net_utils
    )
from typing import Annotated
from typing import Callable
import inspect

mcp = FastMCP(name="UniFiAutomation")

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
def traceroute_syn(destination: Annotated[str, "The server or endpoint to trace ."], remote_host: Annotated[str, "The server to conduct the speedtest with. Required only if the probe is set as the client."], ):
    """Use to perform a TCP SYN traceroute to the spcified destination (server or endpoint) on the specified port (aka service)"""
    routers = net_test.traceroute_syn()

    for pkt in routers:
        logger.info(pkt)

    return routers
    

@mcp.tool
def wifi():
    """WiFi analysis"""

