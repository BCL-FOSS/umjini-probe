from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader
import redis
from utils.network_utils.ProbeInfo import ProbeInfo
import logging
from passlib.hash import bcrypt
from utils.RedisDB import RedisDB
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.NetUtil import NetUtil
from utils.network_utils.NetworkSNMP import NetworkSNMP
import uuid
from passlib.hash import bcrypt
from typing import Callable

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
prb_db = RedisDB(hostname='localhost', port='6379')
probe_utils = ProbeInfo()
net_discovery = NetworkDiscovery()
net_test = NetworkTest()
net_utils = NetUtil(interface='')
net_snmp = NetworkSNMP()

prb_action_map: dict[str, Callable[[dict], object]] = {
    "prbdta": probe_utils.get_probe_data,
    "prbprc": probe_utils.get_processes_by_names,
    "prbprt": probe_utils.open_listening_ports,
    "prbifc": probe_utils.get_iface_ips,
}

dscv_action_map: dict[str, Callable[[dict], object]] = {
    "dscv_full": net_utils.full_discovery,
    "scan_ack": net_discovery.scan_ack,
    "scan_ip": net_discovery.scan_ip,
    "scan_xmas": net_discovery.scan_xmas,
    "dscv_arp": net_discovery.dscv_arp,
    "dscv_dhcp": net_discovery.dscv_dhcp,
    "dscv_tcp": net_discovery.dscv_tcp,
    "dscv_udp": net_discovery.dscv_udp,
}

net_test_action_map: dict[str, Callable[[dict], object]] = {
    "spdtst": net_test.start_iperf,
    "trcrt_dns": net_test.traceroute_dns,
    "trcrt_syn": net_test.traceroute_syn,
    "trcrt_udp": net_test.traceroute_udp,
}

wifi_action_map: dict[str, Callable[[dict], object]] = {
    "wifi_srvy_on": net_utils.start_survey,
    "wifi_srvy_off": net_utils.stop_survey,
    "wifi_srvy_rprt": net_utils.generate_report,
    "wifi_srvy_json": net_utils.get_survey_json,
}

snmp_action_map: dict[str, Callable[[dict], object]] = {}

# local Redis DB Init
r = redis.Redis(host='localhost', port=6379, decode_responses=True)
pong = r.ping()
logger.info(f"Redis ping: {pong}")

def init_probe():
    prb_id, hstnm = probe_utils.gen_probe_register_data()
    cursor, keys = r.scan(cursor=0, match=f'*{hstnm}*')

    if keys:
        for redis_key in keys:
            hash_data = r.hgetall(redis_key)
            logger.info(hash_data)
            prb_id = hash_data.get('prb_id')
            probe_data = hash_data
        return prb_id, hstnm, probe_data
    else:
        probe_data=probe_utils.collect_local_stats(id=f"{prb_id}", hostname=hstnm)
        probe_data['api_key'] = bcrypt.hash(str(uuid.uuid4()))

        # Store probe data
        str_hashmap = {str(k): str(v) for k, v in probe_data.items()}
        result = r.hset(prb_id, mapping=str_hashmap)
        logger.info(result)

        if isinstance(result, int):
            logger.info(f"API Key for umjiniti probe {id}: {probe_data['api_key']}. Store this is a secure location as it will not be displayed again.")
            logger.info(probe_data)
            logger.info(probe_utils.get_ifaces())
            return prb_id, hstnm, probe_data
        else:
            raise SystemExit(130)

# Dependency function to validate the API key
def validate_api_key(key: str = Depends(api_key_header)):
    _, hostname = probe_utils.gen_probe_register_data()
    cursor, keys = r.scan(cursor=0, match=f'*{hostname}*')

    if keys:
        for redis_key in keys:
            hash_data = r.hgetall(redis_key)
            logger.info(hash_data)
            stored_api_key = hash_data.get("api_key")

            if not stored_api_key:
                raise

            if bcrypt.verify(key, stored_api_key):
                return 200
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing API key"
                )
"""
def validate_api_key(key: str = Depends(api_key_header)):
    r = redis.Redis(host='localhost', port=6379)
    pong = r.ping()
    logger.info(pong)
    cursor = b'0'
    id, hostname = probe_utils.gen_probe_register_data()
    cursor, keys = r.scan(cursor=cursor, match=f'*{hostname}*')
    if keys:
        all_data = {}
        for key in keys:
                # Retrieve hash data for each key
            hash_data = r.hgetall(key)
            all_data[key] = {k: v for k, v in hash_data.items()}
            logger.info(all_data.items())

        if bcrypt.verify(key, hash=all_data['api_key']) is False:
            raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing API key"
                )
        else:
            return key

"""
prb_id, hstnm, probe_data = init_probe()
