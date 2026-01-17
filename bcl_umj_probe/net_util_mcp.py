from fastmcp import FastMCP
from typing import Annotated
from utils.network_utils.NetworkTest import NetworkTest
from utils.network_utils.NetworkSNMP import NetworkSNMP
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
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

mcp = FastMCP(name="Network Util MCP")

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

    await log_alert.write_log(log_name=f"dnstraceroute_result", message=log_message)

    return code, output, error

@mcp.tool
async def arp_scan():
    """dnstraceroute is a traceroute utility to figure out the path that a DNS request is passing through to get
       to  its destination.  Comparing it to a network traceroute can help identify if DNS traffic is routed via
       any unwanted path."""
     
    header_data = get_http_headers()
    verify_api(header_data)

    net_discv = NetworkDiscovery()
    net_discv.set_interface(probe_utils.get_ifaces()[0])

    code, output, error = await net_discv.arp_scan()

    log_message=f""
    log_message+=f"{code}\n\n"
    log_message+=f"{output}\n\n"
    log_message+=f"{error}"

    await log_alert.write_log(log_name=f"dnstraceroute_result", message=log_message)

    return code, output, error
    


