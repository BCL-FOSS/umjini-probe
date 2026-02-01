from fastmcp import FastMCP
from typing import Annotated
from utils.network_utils.NetworkTest import NetworkTest
from utils.network_utils.NetworkSNMP import NetworkSNMP
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.PacketCapture import PacketCapture
import logging
import redis
from fastapi import HTTPException, status
from passlib.hash import bcrypt
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from utils.LogAlert import LogAlert
import os

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

probe_utils = ProbeInfo()
net_test = NetworkTest()
net_snmp = NetworkSNMP()
log_alert = LogAlert()

r = redis.Redis(host=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'), decode_responses=True)
pong = r.ping()
logger.info(f"Redis ping: {pong}")

def verify_api(headers: dict[str, str]) -> None:
    key = headers.get("x-api-key")
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key in tool call"
        )
    _, hostname = probe_utils.gen_probe_register_data()
    cursor, keys = r.scan(cursor=0, match=f'*prb-*')

    if keys:
        for redis_key in keys:
            hash_data = r.hgetall(redis_key)
            logger.info(hash_data)
            stored_api_key = hash_data.get("api_key")
            logger.info(stored_api_key)

            if not stored_api_key:
                raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or missing API key"
                )

            if bcrypt.verify(key, stored_api_key):
                return 200
            else:
                raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or missing API key"
                )

mcp = FastMCP(name="umjiniti-probe: network management utility")

@mcp.tool
async def speedtest_server(options: Annotated[str, "Additional command line flags to add to the iperf3 command."] = None, host: Annotated[str, "The IP address of the incoming interface the iperf server binds to. Defaults to 0.0.0.0 to bind to all available interfaces. This should be set for multihomed umjiniti probes."] = None):
    """Runs speedtest server which performs active measurements of the maximum achievable bandwidth on the specified IP network (host). Supports tuning of various parameters related to timing, buffers and protocols (TCP, UDP, SCTP with IPv4 and IPv6) via the command line flag options provided by the user. For each test it reports the bandwidth, loss, and other parameters."""

    header_data = get_http_headers()
    verify_api(header_data)

    if options and host is not None or ''.strip():
        code, output, error = await net_test.iperf_server(options=options, host=host)
        return code, output, error
    
    if options is not None or ''.strip():
        code, output, error = await net_test.iperf_server(options=options)
        return code, output, error
    
    if host is not None or ''.strip():
        code, output, error = await net_test.iperf_server(host=host)
        return code, output, error
    
    code, output, error = await net_test.iperf_server()

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"speedtest_srvr_result", message=log_message)

    return code, output, error

@mcp.tool
async def speedtest_client(server: Annotated[str, "The speedtest server the client connects to."], options: Annotated[str, "Additional command line flags to add to the iperf3 command."] = None, host: Annotated[str, "The IP address of the incoming interface the iperf client binds to. Defaults to 0.0.0.0 to bind to all available interfaces. This should be set for multihomed umjiniti probes."] = None):
    """Starts the client-side of the speedtest to assist with active measurements of the maximum achievable bandwidth from client to the specified server."""

    header_data = get_http_headers()
    verify_api(header_data)

    if options and host is not None or ''.strip():
        code, output, error = await net_test.iperf_client(server=server, options=options, host=host)
        return code, output, error
    
    if options is not None or ''.strip():
        code, output, error = await net_test.iperf_client(server=server, options=options)
        return code, output, error
    
    if host is not None or ''.strip():
        code, output, error = await net_test.iperf_client(server=server, host=host)
        return code, output, error
    
    code, output, error = await net_test.iperf_server()

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"speedtest_client_result", message=log_message)

    return code, output, error

@mcp.tool
async def traceroute(target: Annotated[str, "The server or endpoint to trace."], options: Annotated[str, "Additional command line flags to add to the traceroute command"] = None, packetlength: Annotated[str, "Sets the total size of the probing packet"] = None):
    """traceroute  tracks  the  route packets taken from an IP network on their way to a given host. It utilizes
       the IP protocol's time to live (TTL) field and attempts to elicit an  ICMP  TIME_EXCEEDED  response  from
       each gateway along the path to the host."""

    header_data = get_http_headers()
    verify_api(header_data)

    if options and packetlength is not None or ''.strip():
       code, output, error = await net_test.traceroute(target=target, options=options, packetlen=packetlength)
       return code, output, error

    if options is not None or ''.strip():
       code, output, error = await net_test.traceroute(target=target, options=options)
       return code, output, error

    if packetlength is not None or ''.strip():
        code, output, error = await net_test.traceroute(target=target, packetlen=packetlength)
        return code, output, error

    code, output, error = await net_test.traceroute(target=target)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"
    logger.info(log_message)

    await log_alert.write_log(log_name=f"traceroute_result", message=log_message)

    return code, output, error

@mcp.tool
async def traceroute_dns(target: Annotated[str, "The server or endpoint to trace."], options: Annotated[str, "Additional command line flags to add to the dnstraceroute command"] = None, server: Annotated[str, "The DNS server to use for the traceroute. Defaults to 8.8.8.8 (google DNS server)"] = None):
    """dnstraceroute is a traceroute utility to figure out the path that a DNS request is passing through to get
       to  its destination.  Comparing it to a network traceroute can help identify if DNS traffic is routed via
       any unwanted path."""

    header_data = get_http_headers()
    verify_api(header_data)

    if options and server is not None or ''.strip():
       code, output, error = await net_test.dnstraceroute(target=target, options=options, server=server)
       return code, output, error

    if options is not None or ''.strip():
       code, output, error = await net_test.dnstraceroute(target=target, options=options)
       return code, output, error
    
    if server is not None or ''.strip():
       code, output, error = await net_test.dnstraceroute(target=target, server=server)
       return code, output, error

    code, output, error = await net_test.dnstraceroute(target=target)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"dns_traceroute_result", message=log_message)

    return code, output, error

@mcp.tool
async def arp_scan(interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None):
    """ARP scan uses the ARP protocol to discover and fingerprint IP hosts on the network. Bypasses firewalls that block ICMP. Excellent for device inventory."""
     
    header_data = get_http_headers()
    verify_api(header_data)

    net_discv = NetworkDiscovery()

    iface, network = probe_utils.get_default_interface_subnet()
    net_discv.set_interface(iface=iface)

    if interface is not None:
        net_discv.set_interface(interface)
        network = probe_utils.get_interface_subnet(interface=interface)['network']

    code, output, error = await net_discv.arp_scan(subnet=network)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"arp_scan_result", message=log_message)

    return code, output, error

@mcp.tool
async def device_identifcation_scan(enable_os_detection: Annotated[bool, "Enables OS detection + service identification scan. Service identification is enabled by default (the variable is set to False by default). If OS detection is requested, set this variable to True."] = False, interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None, target: Annotated[str, "The subnet, network device IP or hostname to run the scan on."] = None):
    """Device identification conducts OS and Service (port) identification scans for all endpoints on the network. If OS detection is enabled it creates more traffic noise however the perfomance should be negligible on most networks."""
     
    header_data = get_http_headers()
    verify_api(header_data)

    net_discv = NetworkDiscovery()

    iface, network = probe_utils.get_default_interface_subnet()
    net_discv.set_interface(iface=iface)

    if interface is not None:
        net_discv.set_interface(interface)
        network = probe_utils.get_interface_subnet(interface=interface)['network']

    if enable_os_detection is True and target is not None:
        code, output, error = await net_discv.device_identification_scan(subnet=target, noise=True)

    if enable_os_detection is True:
        code, output, error = await net_discv.device_identification_scan(subnet=network, noise=True)
 
    if target is not None:
        code, output, error = await net_discv.device_identification_scan(subnet=target)
    else:
        code, output, error = await net_discv.device_identification_scan(subnet=network)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"device_id_result", message=log_message)

    return code, output, error

@mcp.tool
async def snmp_scan(type: Annotated[str, "Determines the type of SNMP scan used. To identify if SNMP is active on the specified target, set variable to 'snmp_opn'. If SNMP scripts to run on specified target are provided, set variable to 'snmp_enum'. To retrieve all available SNMP information from the specified target, set variable to 'snmp_all'."] = None, interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None, target: Annotated[str, "The subnet, network device IP or hostname to run the scan on."] = None, scripts: Annotated[str, "The nmap SNMP scan scripts to run. Defaults scripts retrieve system decriptions and system network interface data."] = None):
    """SNMP scan identifies SNMP capable network devices, runs specified nmap SNMP scripts to perform SNMPv3 GET requests and SNMP polling and retireves all available SNMP data for the specified target."""
     
    header_data = get_http_headers()
    verify_api(header_data)

    net_discv = NetworkDiscovery()

    iface, network = probe_utils.get_default_interface_subnet()
    net_discv.set_interface(iface=iface)

    if interface is not None:
        net_discv.set_interface(interface)
        network = probe_utils.get_interface_subnet(interface=interface)['network']

    if target is not None and scripts is not None:
        code, output, error = await net_discv.snmp_scans(subnet=target, type=type, scripts=scripts)

    if scripts is not None:
        code, output, error = await net_discv.snmp_scans(subnet=network, type=type, scripts=scripts)

    if target is not None:
        code, output, error = await net_discv.snmp_scans(subnet=target, type=type)
    else:
        code, output, error = await net_discv.snmp_scans(subnet=network, type=type)


    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"{type}_scan_result", message=log_message)

    return code, output, error

@mcp.tool
async def device_fingerprint_scan(interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None, target: Annotated[str, "The network device IP or hostname to run the scan on."] = None, limit: Annotated[bool, "Enable more aggresive OS detection or limited OS detection. If aggresive OS identification is specified, set variable to False"] = True):
    """Device fingerprint scan performs OS identification for the specified network host or network devices within the specified subnet."""
     
    header_data = get_http_headers()
    verify_api(header_data)

    net_discv = NetworkDiscovery()

    iface, network = probe_utils.get_default_interface_subnet()
    net_discv.set_interface(iface=iface)

    if interface is not None:
        net_discv.set_interface(interface)
        network = probe_utils.get_interface_subnet(interface=interface)['network']

    if target is not None:
        code, output, error = await net_discv.device_fingerprint_scan(subnet=target, limit=limit)
    else:
        code, output, error = await net_discv.device_fingerprint_scan(subnet=network, limit=limit)
  
    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"device_fingerprint_result", message=log_message)

    return code, output, error

@mcp.tool
async def port_scan(interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None, target: Annotated[str, "The network device IP or hostname to run the scan on."] = None, ports: Annotated[str, "The ports to scan for on the specified target. The specified ports should be in the following format: 'port1,port2,port3,port4...'"] = None):
    """Port scan identifies the open ports (services) open on all devices within a subnet or on a specified network host target."""
     
    header_data = get_http_headers()
    verify_api(header_data)

    net_discv = NetworkDiscovery()

    iface, network = probe_utils.get_default_interface_subnet()
    net_discv.set_interface(iface=iface)

    if interface is not None:
        net_discv.set_interface(interface)
        network = probe_utils.get_interface_subnet(interface=interface)['network']

    if target is not None and ports is not None:
        code, output, error = await net_discv.port_scan(subnet=target, ports=ports)

    if target is not None:
        code, output, error = await net_discv.port_scan(subnet=target)

    if ports is not None:
        code, output, error = await net_discv.port_scan(ports=ports)

    else:
        code, output, error = await net_discv.port_scan(subnet=network)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"deviceid_result", message=log_message)

    return code, output, error

@mcp.tool
async def custom_scan( options: Annotated[str, "The nmap scan options to run."], interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None, target: Annotated[str, "The network device IP or hostname to run the scan on."] = None):
    """Custom scan runs an nmap scan with the specified commandline options on all devices within a subnet or on the specified network host target."""
     
    header_data = get_http_headers()
    verify_api(header_data)

    net_discv = NetworkDiscovery()

    iface, network = probe_utils.get_default_interface_subnet()
    net_discv.set_interface(iface=iface)

    if interface is not None:
        net_discv.set_interface(interface)
        network = probe_utils.get_interface_subnet(interface=interface)['network']

    if target is not None and options is not None:
        code, output, error = await net_discv.custom_scan(subnet=target, options=options)
    
    if options is not None:
        code, output, error = await net_discv.custom_scan(subnet=network, options=options)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"deviceid_result", message=log_message)

    return code, output, error

@mcp.tool
async def full_scan(interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None):
    """Full scan runs a full network device discovery an a specified subnet. Enable OS detection, version detection, script scanning, and traceroute."""
     
    header_data = get_http_headers()
    verify_api(header_data)

    net_discv = NetworkDiscovery()

    iface, network = probe_utils.get_default_interface_subnet()
    net_discv.set_interface(iface=iface)

    if interface is not None:
        net_discv.set_interface(interface)
        network = probe_utils.get_interface_subnet(interface=interface)['network']

    code, output, error = await net_discv.full_network_scan(subnet=network)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"deviceid_result", message=log_message)

    return code, output, error

@mcp.tool
async def pcap_local(interface: Annotated[str, "The physical network interface port the packet capture will run on. Defaults to the primary interface on the host."] = None, cap_count: Annotated[int, "The number of packets to capture. Default is set to 50."] = None):
    """pcap local captures and logs ingress and egress traffic on a local network interface using tcpdump. PCAP results are stored in '/home/quart/probedata/pcaps'."""

    header_data = get_http_headers()
    verify_api(header_data)

    pcap = PacketCapture()

    iface, network = probe_utils.get_default_interface_subnet()

    if interface is not None and cap_count is not None:
        code, output, error = await pcap.pcap_local(interface=interface, cap_count=cap_count)

    if interface is not None:
        code, output, error = await pcap.pcap_local(interface=interface)

    if cap_count is not None:
        code, output, error = await pcap.pcap_local(interface=iface, cap_count=cap_count)

    if cap_count is None and interface is None:
        code, output, error = await pcap.pcap_local(interface=iface)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"deviceid_result", message=log_message)

    return code, output, error

@mcp.tool
async def pcap_remote_linux(remote_interface: Annotated[str, "The physical network interface port of the remote linux host the packet capture will run on."], host: Annotated[str, "the remote linux host the packet capture will run on."], username: Annotated[str, "The username of a sudo level user of the remote linux host."], password: Annotated[str, "The password of the sudo level user on the remote linux host."], cap_count: Annotated[int, "The number of packets to capture. Default is set to 50."] = None):
    """pcap remote linux captures and logs ingress and egress traffic on a remote linux host's specified network interface using tcpdump. Rsync copies the remote PCAPS results from the remote linux host to the local probe '/probedata/pcaps' directory."""

    header_data = get_http_headers()
    verify_api(header_data)

    pcap = PacketCapture()

    pcap.set_host(host=host)

    pcap.set_credentials(user=username, password=password)

    if cap_count is not None:
        code, output, error = await pcap.pcap_remote_linux(remote_iface=remote_interface, cap_count=cap_count)
    else:
        code, output, error = await pcap.pcap_remote_linux(remote_iface=remote_interface)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"deviceid_result", message=log_message)

    return code, output, error

@mcp.tool
async def pcap_remote_windows(remote_interface: Annotated[str, "The physical network interface port of the remote windows server host the packet capture will run on."], host: Annotated[str, "the remote windows server host the packet capture will run on."], username: Annotated[str, "The username of an admin level user of the remote linux host."], password: Annotated[str, "The password of an admin level user on the remote linux host."], duration: Annotated[int, "The number of seconds the packet capture will run on the windows server host."] = None):
    """pcap remote windows captures and logs ingress and egress traffic on a remote windows host's specified network interface using tshark (commandline wireshark) and npcap. Remote PCAP results are written to the local '/probedata/pcaps' directory from the stdout output from the ssh session."""

    header_data = get_http_headers()
    verify_api(header_data)

    pcap = PacketCapture()

    pcap.set_host(host=host)

    pcap.set_credentials(user=username, password=password)

    if duration is not None:
        code, output, error = await pcap.pcap_remote_windows(remote_iface=remote_interface, duration=duration)
    else:
        code, output, error = await pcap.pcap_remote_linux(remote_iface=remote_interface)

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"deviceid_result", message=log_message)

    return code, output, error











    


