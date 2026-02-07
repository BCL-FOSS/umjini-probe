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
from utils.LogAlert import LogAlert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))

net_discovery = NetworkDiscovery()
net_test = NetworkTest()
pcap = PacketCapture()
probe_util = ProbeInfo()
log_alert = LogAlert()

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

async def automate_task(action: str, params: str, ws_url: str, probe_data: str):
    async with connect(uri=ws_url) as websocket:
        params_dict = json.loads(params)
        probe_data_dict = json.loads(probe_data)

        if action == 'pcap_tux' or action == 'pcap_win':
            pcap.set_host(host=params_dict['host'])
            pcap.set_credentials(user=params_dict['usr'], password=params_dict['pwd'])

        handler = action_map.get(action)
        if handler and params_dict:
            code, output, error = await handler(**params_dict)

        if code != 0:
            log_message=f""
            log_message+=f"{code}\n\n"
            log_message+=f"{output}\n\n"
            log_message+=f"{error}"

            timestamp = datetime.now(tz=timezone.utc).isoformat()

            await log_alert.write_log(log_name=f"{action}_result_{timestamp}", message=log_message)

            task_result = {
                'site': probe_data_dict['site'],
                'task_output': output,
                'prb_id': probe_data_dict['prb_id'],
                'name': probe_data_dict['name'],
                'task_type': f'{action}',
                'act': "prb_task_rslt",
                'llm': params_dict['llm']
                }
            
            await websocket.send(json.dumps(task_result))
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
    parser.add_argument(
        '-pdta', '--probe_data', 
        type=dict, 
        help="Probe data for reporting results"
    )
    args = parser.parse_args()

    asyncio.run(automate_task(action=args.action, params=args.params, ws_url=args.ws_url, prb_id=args.prb_id, site=args.site, llm=args.llmanalysis, probe_data=args.probe_data))