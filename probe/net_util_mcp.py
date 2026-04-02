from fastmcp import FastMCP
from typing import Annotated
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from init_app import log_alert, validate_mcp_api_key
from auto_scripts.script_base.base import run_task
import json

mcp = FastMCP(name="umjiniti-probe: network management utility")

async def save_log_and_return(code: int, output: str, error: str, log_name: str) -> tuple[int, str, str]:
    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"
    await log_alert.write_log(log_name=log_name, message=log_message)
    return code, output, error

@mcp.tool
async def test_srvr(options: Annotated[str, "Additional command line flags to add to the iperf3 command."] = None, host: Annotated[str, "The IP address of the incoming interface the iperf server binds to. Defaults to 0.0.0.0 to bind to all available interfaces. This should be set for multihomed umjiniti probes."] = None):
    """Runs speedtest server which performs active measurements of the maximum achievable bandwidth on the specified IP network (host). Supports tuning of various parameters related to timing, buffers and protocols (TCP, UDP, SCTP with IPv4 and IPv6) via the command line flag options provided by the user. For each test it reports the bandwidth, loss, and other parameters."""

    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {'tool_prms': {}}
    
    if options and options.strip() != '':
        params['tool_prms']['options'] = options
    
    if host and host.strip() != '':
        params['tool_prms']['host'] = host
    
    code, output, error, _ = await run_task(action="test_srvr", params=json.dumps(params))
    return await save_log_and_return(code, output, error, log_name=f"speedtest_srvr_result")

@mcp.tool
async def test_clnt(server: Annotated[str, "The speedtest server the client connects to."], options: Annotated[str, "Additional command line flags to add to the iperf3 command."] = None, host: Annotated[str, "The IP address of the incoming interface the iperf client binds to. Defaults to 0.0.0.0 to bind to all available interfaces. This should be set for multihomed umjiniti probes."] = None):
    """Starts the client-side of the speedtest to assist with active measurements of the maximum achievable bandwidth from client to the specified server."""

    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {'tool_prms': {}}
    
    if options and options.strip() != '':
        params['tool_prms']['options'] = options
      
    if host and host.strip() != '':
        params['tool_prms']['host'] = host
    
    params['tool_prms']['server'] = server
    code, output, error, _ = await run_task(action="test_clnt", params=json.dumps(params))
    return await save_log_and_return(code, output, error, log_name=f"speedtest_client_result")

@mcp.tool
async def trcrt(target: Annotated[str, "The server or endpoint to trace."], options: Annotated[str, "Additional command line flags to add to the traceroute command"] = None, packetlength: Annotated[str, "Sets the total size of the probing packet"] = None):
    """traceroute  tracks  the  route packets taken from an IP network on their way to a given host. It utilizes
       the IP protocol's time to live (TTL) field and attempts to elicit an  ICMP  TIME_EXCEEDED  response  from
       each gateway along the path to the host."""

    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {'tool_prms': {}}

    if options and options.strip() != '':
       params['tool_prms']['options'] = options

    if packetlength and packetlength.strip() != '':
        params['tool_prms']['packetlen'] = packetlength

    params['tool_prms']['target'] = target
    code, output, error, _ = await run_task(action="trcrt", params=json.dumps(params))

    return await save_log_and_return(code, output, error, log_name=f"traceroute_result")

@mcp.tool
async def trcrt_dns(target: Annotated[str, "The server or endpoint to trace."], options: Annotated[str, "Additional command line flags to add to the dnstraceroute command"] = None, server: Annotated[str, "The DNS server to use for the traceroute. Defaults to 8.8.8.8 (google DNS server)"] = None):
    """dnstraceroute is a traceroute utility to figure out the path that a DNS request is passing through to get
       to  its destination.  Comparing it to a network traceroute can help identify if DNS traffic is routed via
       any unwanted path."""

    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {'tool_prms': {}}

    if options and options.strip() != '':
        params['tool_prms']['options'] = options
     
    if server and server.strip() != '':
       params['tool_prms']['server'] = server
       
    params['tool_prms']['target'] = target
    code, output, error, _ = await run_task(action="trcrt_dns", params=json.dumps(params))

    return await save_log_and_return(code, output, error, log_name=f"dns_traceroute_result")

@mcp.tool
async def scan_vuln(target: Annotated[str, "The subnet, network device IP or hostname to run the scan on."], interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None, min_score: Annotated[int, "The minimum CVSS score to filter vulnerabilities. Defaults to 5."] = None):
    """scan_vuln runs a vulnerability scan against the specified target. will return list of CVEs with a CVSS score of 5 or higher by default. The scan uses the nmap vulners script which leverages the vulners.com vulnerability database to perform vulnerability detection based on the software and services running on the target host(s)."""
     
    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {'tool_prms': {}}

    if interface and interface.strip() != '':
        params['interface'] = interface

    if min_score is not None:
        params['tool_prms']['min_score'] = str(min_score)

    params['tool_prms']['target'] = target
    code, output, error, _ = await run_task(action="scan_vuln", params=json.dumps(params))
    return await save_log_and_return(code, output, error, log_name=f"vulnerability_scan_result")

@mcp.tool
async def scan_srvc(target: Annotated[str, "The subnet, network device IP or hostname to run the scan on."], interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None):
    """Identifies all running services on the specified target by performing a nmap service/version detection scan (-sV)."""
     
    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {'tool_prms': {}}

    if interface and interface.strip() != '':
        params['interface'] = interface
       
    params['tool_prms']['target'] = target
    code, output, error, _ = await run_task(action="scan_dev_id", params=json.dumps(params))
    return await save_log_and_return(code, output, error, log_name=f"device_id_scan_result")

@mcp.tool
async def scan_snmp(target: Annotated[str, "The subnet, network device IP or hostname to run the scan on."], interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None,  scripts: Annotated[str, "The nmap SNMP scan scripts to run. Defaults scripts retrieve system decriptions and system network interface data."] = None, community: Annotated[str, "The SNMP community string to use for the scan."] = None):
    """SNMP scan identifies SNMP capable network devices, runs specified nmap SNMP scripts to perform SNMPv3 GET requests and SNMP polling and retireves all available SNMP data for the specified target."""
     
    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {'tool_prms': {}}

    if interface and interface.strip() != '':
        params['interface'] = interface

    if scripts and scripts.strip() != '':
        params['tool_prms']['scripts'] = scripts

    if community and community.strip() != '':
        params['tool_prms']['target'] = target
        code, output, error, _ = await run_task(action="scan_snmp", params=json.dumps(params), snmp_community=community)
        return await save_log_and_return(code, output, error, log_name=f"snmp_scan_result")
        
    params['tool_prms']['target'] = target
    code, output, error, _ = await run_task(action="scan_snmp", params=json.dumps(params))
    return await save_log_and_return(code, output, error, log_name=f"snmp_scan_result")

@mcp.tool
async def scan_custom(target: Annotated[str, "The network device IP or hostname to run the scan on."], options: Annotated[str, "The nmap scan options to run."], interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None):
    """Custom scan runs an nmap scan with the specified commandline options on all devices within a subnet or on the specified network host target."""
     
    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {'tool_prms': {}}

    if interface and interface.strip() != '':
        params['interface'] = interface

    if options and options.strip() != '':
        params['tool_prms']['options'] = options

    if target and target.strip() != '':
        params['tool_prms']['target'] = target

    code, output, error, _ = await run_task(action="scan_custom", params=json.dumps(params))
    return await save_log_and_return(code, output, error, log_name=f"custom_scan_result")

@mcp.tool
async def scan_map(target: Annotated[str, "The network device IP or hostname to run the scan on."], interface: Annotated[str, "The physical network interface port the scan will run on. Defaults to the primary interface on the host."] = None, syn_ports: Annotated[str, "The TCP SYN ports to use for host discovery in the nmap scan. Defaults to 22,23,80,443,830,3389."] = None, ack_ports: Annotated[str, "The TCP ACK ports to use for host discovery in the nmap scan. Defaults to 80,443."] = None):
    """Full scan runs a full network device discovery an a specified subnet. Enable OS detection, version detection, script scanning, and traceroute."""

    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {'tool_prms': {}}

    if interface and interface.strip() != '':
        params['interface'] = interface

    if syn_ports and syn_ports.strip() != '':
        params['tool_prms']['syn_ports'] = syn_ports

    if ack_ports and ack_ports.strip() != '':
        params['tool_prms']['ack_ports'] = ack_ports

    params['tool_prms']['target'] = target
    code, output, error, _ = await run_task(action="scan_full", params=json.dumps(params))

    return await save_log_and_return(code, output, error, log_name=f"full_scan_result")

@mcp.tool
async def pcap_lcl(interface: Annotated[str, "The physical network interface port the packet capture will run on. Defaults to the primary interface on the host."] = None, cap_count: Annotated[int, "The number of packets to capture. Default is set to 50."] = None):
    """pcap local captures and logs ingress and egress traffic on a local network interface using tcpdump. PCAP results are stored in '/home/quart/probedata/pcaps'."""

    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {}

    if interface and interface.strip() != '':
        params['interface'] = interface

    if cap_count is not None:
        params['cap_count'] = cap_count

    code, output, error, _ = await run_task(action="pcap_lcl", params=json.dumps(params))

    return await save_log_and_return(code, output, error, log_name=f"pcap_local_result")

@mcp.tool
async def pcap_tux(remote_interface: Annotated[str, "The physical network interface port of the remote linux host the packet capture will run on."], host: Annotated[str, "the remote linux host the packet capture will run on."], username: Annotated[str, "The username of a sudo level user of the remote linux host."], password: Annotated[str, "The password of the sudo level user on the remote linux host."], cap_count: Annotated[int, "The number of packets to capture. Default is set to 50."] = None):
    """pcap remote linux captures and logs ingress and egress traffic on a remote linux host's specified network interface using tcpdump. Rsync copies the remote PCAPS results from the remote linux host to the local probe '/probedata/pcaps' directory."""

    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {}

    if remote_interface and remote_interface.strip() != '':
        params['remote_interface'] = remote_interface

    if (host and host.strip() != '') and (username and username.strip() != '') and (password and password.strip() != ''):
        params['host'] = host
        params['usr'] = username
        params['pwd'] = password

    if cap_count is not None:
        params['cap_count'] = cap_count

    code, output, error, _ = await run_task(action="pcap_tux", params=json.dumps(params))

    return await save_log_and_return(code, output, error, log_name=f"pcap_tux_result")

@mcp.tool
async def pcap_win(remote_interface: Annotated[str, "The physical network interface port of the remote windows server host the packet capture will run on."], host: Annotated[str, "the remote windows server host the packet capture will run on."], username: Annotated[str, "The username of an admin level user of the remote windows host."], password: Annotated[str, "The password of an admin level user on the remote windows host."], duration: Annotated[int, "The number of seconds the packet capture will run on the windows server host."] = None):
    """pcap remote windows captures and logs ingress and egress traffic on a remote windows host's specified network interface using tshark (commandline wireshark) and npcap. Remote PCAP results are written to the local '/probedata/pcaps' directory from the stdout output from the ssh session."""

    header_data = get_http_headers()
    await validate_mcp_api_key(header_data)
    params = {}

    if remote_interface and remote_interface.strip() != '':
        params['remote_iface'] = remote_interface

    if (host and host.strip() != '') and (username and username.strip() != '') and (password and password.strip() != ''):
        params['host'] = host
        params['usr'] = username
        params['pwd'] = password

    if duration is not None:
        params['duration'] = duration

    code, output, error, _ = await run_task(action="pcap_win", params=json.dumps(params))

    return await save_log_and_return(code, output, error, log_name=f"pcap_win_result")
