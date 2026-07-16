from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader
import redis
from utils.network_utils.ProbeInfo import ProbeInfo
import logging
from passlib.hash import bcrypt
import os
from typing import Callable
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.PacketCapture import PacketCapture
from utils.alerts_utils.SlackAlert import SlackAlert
from utils.alerts_utils.JiraSM import JiraSM
from utils.alerts_utils.EmailSenderHandler import EmailSenderHandler
from utils.alerts_utils.BotConnection import BotConnection
import logging
from crontab import CronTab
from utils.alerts_utils.LogAlert import LogAlert
from utils.Parsers import Parsers
from utils.RedisDB import RedisDB
import asyncio

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logging.getLogger("fakeredis").setLevel(logging.WARNING)
logging.getLogger("docket.worker").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
net_discovery = NetworkDiscovery()
net_test = NetworkTest()
pcap = PacketCapture()
probe_util = ProbeInfo()
log_alert = LogAlert()
slack_alert = SlackAlert()
jira_alert = JiraSM()
email_alert = EmailSenderHandler()
bot_connection = BotConnection()
parsers = Parsers()
cron=CronTab(user='root')  
action_map: dict[str, Callable[[dict], object]] = {
    "trcrt_dns": net_test.dnstraceroute,
    "trcrt": net_test.traceroute,
    "test_srvr": net_test.iperf_server,
    "test_clnt": net_test.iperf_client,
    "scan_vuln": net_discovery.vulnerabilities,
    "scan_snmp": net_discovery.snmp,
    "scan_os": net_discovery.operating_system,
    "scan_srvc": net_discovery.services,
    "scan_cust": net_discovery.custom,
    "scan_map": net_discovery.mapper,
    "pcap_lcl": pcap.pcap_local,
    "pcap_tux": pcap.pcap_remote_linux,
    "pcap_win": pcap.pcap_remote_windows,
    "slack": slack_alert.send_alert_message,
    "jira": jira_alert.send_alert,
    "bot": bot_connection.mcp_exec,
    "email": email_alert.send_transactional_email,
}
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
error_response = 'missing required data'

def init_probe():
    db_init = asyncio.run(prb_db.connect_db())
    if db_init is None:
        exit(1)

    prb_id, hstnm = probe_util.gen_probe_register_data()
    
    if os.environ.get('DEFAULT_INTERFACE') is None:
        net_discovery.set_interface(probe_util.get_ifaces()[0])
    else:
        net_discovery.set_interface(os.environ.get('DEFAULT_INTERFACE'))

    probe_data_check = asyncio.run(prb_db.get_all_data(match='*prb:*', cnfrm=True))

    if probe_data_check is False:
        probe_data=probe_util.collect_local_stats(id=f"{prb_id}", hostname=hstnm)
        host_interfaces = probe_util.get_ifaces()
        probe_data['iface_list'] = host_interfaces
        logger.info(host_interfaces)

        data_uploaded = asyncio.run(prb_db.upload_db_data(id=f"{prb_id}", data=probe_data))
        if data_uploaded is None:
            logger.error(f"Failed to upload probe data to Redis for probe ID: {prb_id}")
            exit(1)

        if data_uploaded > 0:
            return prb_id, hstnm, probe_data

    elif probe_data_check is True:
        probe_data = asyncio.run(prb_db.get_all_data(match='*prb:*'))
        probe_data_dict = next(iter(probe_data.values()))
        prb_id = probe_data_dict.get('prb_id')
        hstnm = probe_data_dict.get('hstnm')
        return prb_id, hstnm, probe_data
    
async def check_api_key(key: str):
    probe_data = await prb_db.get_all_data(match='*prb:*')
    probe_data_dict = next(iter(probe_data.values()))
    stored_api_key = probe_data_dict.get("api_key")
    
    if not stored_api_key or not bcrypt.verify(key, stored_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid"
        )
    else:
        return 200
            
async def validate_api_key(key: str = Depends(api_key_header)):
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response
        )
    if await prb_db.get_all_data(match='*prb:*', cnfrm=True) is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response
        )
    await check_api_key(key)
            
async def validate_mcp_api_key(headers: dict[str, str]) -> None:
    key = headers.get("x-api-key")
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response
        )
    if await prb_db.get_all_data(match='*prb:*', cnfrm=True) is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response
        )
    await check_api_key(key)
    

