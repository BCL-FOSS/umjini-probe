from datetime import datetime
from uuid import uuid4
import asyncio
import argparse
import os
from passlib.hash import bcrypt
import logging
from datetime import datetime, timedelta, timezone
from typing import Callable
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.PacketCapture import PacketCapture
from websockets.asyncio.client import connect
import json
from utils.RedisDB import RedisDB

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))

net_discovery = NetworkDiscovery()
net_test = NetworkTest()
pcap = PacketCapture()
probe_util = ProbeInfo()

net_discovery.set_interface(probe_util.get_ifaces()[0])

action_map: dict[str, Callable[[dict], object]] = {
    "trcrt_dns": net_test.dnstraceroute,
    "trcrt": net_test.traceroute,
    "test_srvr": net_test.iperf_server,
    "test_clnt": net_test.iperf_client,
    "scan_arp": net_discovery.arp_scan,
    "scan_custom": net_discovery.custom_scan,
    "scan_dev_id": net_discovery.device_identification_scan,
    "scan_dev_fngr": net_discovery.device_fingerprint_scan,
    "scan_full": net_discovery.full_network_scan,
    "scan_snmp": net_discovery.snmp_scans,
    "scan_port": net_discovery.port_scan,
    "pcap_lcl": pcap.pcap_local,
    "pcap_tux": pcap.pcap_remote_linux,
    "pcap_win": pcap.pcap_remote_windows
}

async def automate_task(action: str, params: dict, ws_url: str, prb_id: str, site: str, llm: str):
    async with connect(uri=ws_url) as websocket:
        handler = action_map.get(action)
        if handler:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**params)
            else:
                result = handler(**params)

            umj_result_data = {
                'site': site,
                'act_rslt': result,
                'prb_id': prb_id,
                'act_rslt_type': f'{action}',
                'llm': llm,
                'act': "prb_task_rslt"
                }
            
            await websocket.send(json.dumps(umj_result_data))
        else:
            logger.error(f"Action '{action}' not found in action map.")
            return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate network monitoring tasks.")
    parser.add_argument(
        '-a', '--action', 
        type=str, 
        help="Network task to perform"
    )
    parser.add_argument(
        '-p', '--params', 
        type=dict, 
        help="Parameters for the network task"
    )
    parser.add_argument(
        '-w', '--ws_url', 
        type=str, 
        help="WebSocket URL for reporting results"
    )
    parser.add_argument(
        '-pid', '--prb_id', 
        type=str, 
        help="Probe " \
        "ID for reporting results"
    )
    parser.add_argument(
        '-s', '--site', 
        type=str, 
        help="Site for reporting results"
    )
    parser.add_argument(
        '-llm', '--llmanalysis', 
        action='store_true', 
        help="Enable debug logging"
    )
    args = parser.parse_args()

    asyncio.run(automate_task(action=args.action, params=args.params, ws_url=args.ws_url, prb_id=args.prb_id, site=args.site, llm=args.llmanalysis))