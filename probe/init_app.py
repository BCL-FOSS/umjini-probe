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
r = redis.Redis(host=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'), decode_responses=True)
pong = r.ping()
logger.info(f"Redis ping: {pong}")
error_response = 'missing required data'

def init_probe():
    db_init = asyncio.run(prb_db.connect_db())
    if db_init is None:
        exit(1)

    prb_id, hstnm = probe_util.gen_probe_register_data()
    _, keys = r.scan(cursor=0, match=f'*prb:*')

    if os.environ.get('DEFAULT_INTERFACE') is None:
        net_discovery.set_interface(probe_util.get_ifaces()[0])
    else:
        net_discovery.set_interface(os.environ.get('DEFAULT_INTERFACE'))

    if not keys:
        probe_data=probe_util.collect_local_stats(id=f"{prb_id}", hostname=hstnm)
        host_interfaces = probe_util.get_ifaces()
        probe_data['iface_list'] = host_interfaces
        logger.info(host_interfaces)

        str_hashmap = {str(k): str(v) for k, v in probe_data.items()}
        result = r.hset(prb_id, mapping=str_hashmap)
        logger.info(result)

        if isinstance(result, int):
            return prb_id, hstnm, probe_data

    if keys:
        for redis_key in keys:
            hash_data = r.hgetall(redis_key)
            logger.info(hash_data)
            prb_id = hash_data.get('prb_id')
            probe_data = hash_data
        return prb_id, hstnm, probe_data
            
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
