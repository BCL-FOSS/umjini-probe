import asyncio
import websockets
import os
from websockets import ClientConnection, ConnectionClosed
from typing import Callable
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.PacketCapture import PacketCapture
import os
import logging
import inspect
from utils.RedisDB import RedisDB
import httpx

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
    "arp": net_discovery.arp_scan,
    "dev_classify": net_discovery.custom_scan,
    "dev_id": net_discovery.device_identification_scan,
    "dev_fngr": net_discovery.device_fingerprint_scan,
    "net_scan": net_discovery.full_network_scan,
    "snmp_scans": net_discovery.snmp_scans,
    "service_id": net_discovery.port_scan,
    "pcap_lcl": pcap.pcap_local,
    "pcap_tux": pcap.pcap_remote_linux,
    "pcap_win": pcap.pcap_remote_windows
}

class CoreClient:
    def __init__(self, umj_url: str, umj_token: str, umj_ws_url: str):
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.logger = logging.getLogger(__name__)
        self.umj_url = umj_url
        self.umj_token = umj_token
        self.umj_ws = umj_ws_url
        self.prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))

    async def make_request(self, url: str, umj_key: str = None):
        async with httpx.AsyncClient() as client:
            headers = {"X-UMJ-WFLW-API-KEY": umj_key}
            return await client.get(url=url, headers=headers)

    async def connect_with_backoff(self, ws_url: str, access_token: str, init_url: str):
        backoff = 1
        await self.prb_db.connect_db()
        probe_data = await self.prb_db.get_all_data(match='prb-*')
        probe_data_dict = next(iter(probe_data.values()))

        while True:
            headers = {
                "Cookie": f"access_token={access_token}"
            }

            try:
                async with websockets.connect(
                    uri=ws_url,
                    additional_headers=headers
                ) as ws:
                    self.logger.info(f"Connected to {ws_url}")
                    backoff = 1  # reset backoff on success
                    await self.interact(ws, probe_obj=probe_data_dict)

            except (ConnectionClosed, Exception) as e:
                self.logger.error(f"WebSocket error: {e}")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
                umj_api_key = probe_data_dict.get('umj_api_key')

                umj_response = await self.make_request(
                    url=init_url,
                    umj_key=umj_api_key
                )

                if umj_response.status_code != 200:
                    self.logger.error("Failed to refresh access_token")
                    return

                access_token = umj_response.cookies.get("access_token")
                if not access_token:
                    self.logger.error("No access_token returned")
                    return

    async def interact(self, ws: ClientConnection, probe_obj: dict):
        async def receive():
            while True:
                raw_message = await ws.recv()

                if isinstance(raw_message, dict):
                    probe_id = raw_message.get('prb_id')
                    if probe_id and probe_id == probe_obj.get('prb_id'):
                        action = raw_message.get("act")
                        params = raw_message.get("prms")

                        match action:
                            case 'pcap_tux' | 'pcap_win':
                                pcap.set_host(host=raw_message.get('host'))
                                pcap.set_credentials(user=raw_message.get('usr'), password=raw_message.get('pwd'))
                                
                        # handle probe actions sent from umjiniti core
                        handler = action_map.get(action)
                        if handler and params:
                            if inspect.iscoroutinefunction(handler):
                                result = await handler(**params)
                            else:
                                result = handler(**params)
                        
                        if handler:
                            if inspect.iscoroutinefunction(handler):
                                result = await handler()
                            else:
                                result = handler()
                            
                        umj_result_data = {}
                        umj_result_data['site'] = probe_obj.get('site')
                        umj_result_data['act_rslt'] = result
                        umj_result_data['prb_id'] = probe_obj.get('prb_id')
                        umj_result_data['type'] = f'{action}_rslt_msg'

                        await ws.send(umj_result_data)
                else:
                    pass 
                
        async def heartbeat():
            ping = {
                    "sess_id": probe_obj.get('prb_id'),
                    "site": probe_obj.get('site'), 
                    "act": "heart_beat"
                    }
            
            while True:
                await ws.send(ping)
                await asyncio.sleep(30)

        async def netmap():
            
            await net_discovery.arp_scan()
            ping = {
                    "sess_id": probe_obj.get('prb_id'),
                    "site": probe_obj.get('site'), 
                    "act": "net_map"
                    }
            
            while True:
                await ws.send(ping)
                await asyncio.sleep(600)

        await asyncio.gather(receive(), heartbeat(), netmap())

    def run(self):
        asyncio.run(self.connect_with_backoff(ws_url=self.umj_ws, init_url=self.umj_url, cookie=self.umj_token))