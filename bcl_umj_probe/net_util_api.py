from contextlib import asynccontextmanager
from time import timezone
from fastapi import FastAPI, Depends, Response
from fastapi_user_limiter.limiter import rate_limiter
from pydantic import BaseModel
from init_app import (
    validate_api_key,
    init_probe
)
import httpx
import logging
from net_util_mcp import mcp
import os
from utils.RedisDB import RedisDB
from CoreClientv2 import CoreClient
import asyncio
import xmltodict
import json
from typing import Callable
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.PacketCapture import PacketCapture
from datetime import datetime, timedelta, timezone
import inspect

class InitCall(BaseModel):
    umj_url: str 
    umj_usr: str
    umj_site: str
    umj_api_key: str
    prb_url: str
    prb_api_key: str
    prb_name: str

class ScanCall(BaseModel):
    scan_type: str
    interface: str
    file_name: str
    params: dict

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
prb_id, hstnm, probe_data = init_probe()
probe_util = ProbeInfo()
net_discovery = NetworkDiscovery()
net_test = NetworkTest()
pcap = PacketCapture()

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

logger.info(f"Probe initialized id={prb_id}, hostname={hstnm}")

mcp_app = mcp.http_app(path="/mcp")

@asynccontextmanager
async def combined_lifespan(app:FastAPI):
    async with mcp_app.lifespan(app):
        # idempotent guard
        if getattr(app.state, "core_client_started", False) is False:
            app.state.core_client_started = True
            app.state.core_client = None
            app.state.core_client_task = None
            app.state.core_client_stop = None

            if probe_data.get("umj_url"):
                ws_url = f"wss://{probe_data.get('umj_url')}/heartbeat/{probe_data.get('prb_id')}"
                core_client = CoreClient(umj_ws_url=ws_url)
                stop_event = asyncio.Event()
                app.state.core_client_stop = stop_event
                app.state.core_client = core_client
                app.state.core_client_task = asyncio.create_task(core_client.run(stop_event))
                logger.info("Started CoreClient task in FastAPI lifespan")
        
        yield
        
        stop_event = getattr(app.state, "core_client_stop", None)
        task = getattr(app.state, "core_client_task", None)

        if stop_event is not None:
            stop_event.set()

        if task is not None:
            try:
                await asyncio.wait_for(task, timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning("CoreClient task did not exit in time; cancelling")
                task.cancel()
                try:
                    await task
                except Exception:
                    pass

            logger.info("CoreClient stopped and combined_lifespan exiting")

api = FastAPI(title='Network Util API', lifespan=combined_lifespan)

async def _make_http_request(cmd: str, url: str, payload: dict = {}, headers: dict = {}, cookies: str = ''):
    async with httpx.AsyncClient() as client:
        if cmd == 'p':
            client.cookies.set("access_token", value=cookies)
            return await client.post(url, json=payload, headers=headers)
        elif cmd == 'g':
            return await client.get(url, headers=headers)
        
@api.get("/v1/api/status", dependencies=[Depends(rate_limiter(2, 5))])
def status():
    return Response(content='{"status": "ok"}', media_type="application/json", status_code=200)

@api.post("/v1/api/init", dependencies=[Depends(validate_api_key)])
async def init(init_data: InitCall):
    init_url = f"https://{init_data.umj_url}/init?usr={init_data.umj_usr}"
    logger.info(init_url)
    enroll_url = f"https://{init_data.umj_url}/enroll?usr={init_data.umj_usr}&site={init_data.umj_site}"
    logger.info(enroll_url)

    async def enrollment(payload: dict = {}):
        headers = {"X-UMJ-WFLW-API-KEY": init_data.umj_api_key}
        post_headers = {"X-UMJ-WFLW-API-KEY": init_data.umj_api_key,
                        "Content-Type": "application/json"}

        resp_data = await _make_http_request(cmd="g", url=init_url, headers=headers)
        if resp_data.status_code == 200:
            access_token = resp_data.cookies.get("access_token")
            logger.info(access_token)
            await resp_data.aclose()

            enroll_rqst = await _make_http_request(
                cmd="p",
                url=enroll_url,
                headers=post_headers,
                cookies=access_token,
                payload=payload,
            )
            await enroll_rqst.aclose()
            return 200 if enroll_rqst.status_code == 200 else 400
        else:
            await resp_data.aclose()

        return None
    
    await prb_db.connect_db()

    probe_data['url'] = init_data.prb_url
    probe_data['prb_api_key'] = init_data.prb_api_key
    probe_data['site'] = init_data.umj_site
    probe_data['name'] = init_data.prb_name
    probe_data['assigned_user'] = init_data.umj_usr
    logger.info(probe_data)

    if await enrollment(payload=probe_data) != 200:
        return Response(content='{"Error": "occurred during probe adoption"}', media_type="application/json", status_code=400)
    else:
        probe_info = await prb_db.get_all_data(match=f"prb-*")
        probe_info_dict = next(iter(probe_info.values()))
        probe_id = probe_info_dict.get('prb_id')

        umj_probe_data = {'url': init_data.prb_url,
                          'site': init_data.umj_site,
                          'name': init_data.prb_name,
                          'assigned_user': init_data.umj_usr,
                          'umj_url': init_data.umj_url
                          }

        if await prb_db.upload_db_data(id=probe_id, data=umj_probe_data) > 0:
            return Response(content='{"status": "ok"}', media_type="application/json", status_code=200)
        else:
            return Response(content='{"Error": "occurred during probe adoption"}', media_type="application/json", status_code=400)

@api.post("/v1/api/probe/{probe_id}/scan", dependencies=[Depends(validate_api_key)])
async def run_network_scan(probe_id: str, scan_data: ScanCall):
    try:
        params = scan_data.params
        
        await prb_db.connect_db()
        probe_info = await prb_db.get_all_data(match=f"{probe_id}")
        
        if not probe_info:
            return Response(
                content='{"error": "Probe not found"}',
                media_type="application/json",
                status_code=404
            )
        
        cur_dir = os.getcwd()

        scan_dir = os.path.join(cur_dir, "nmap_scans")

        if not os.path.exists(scan_dir):
            os.makedirs(scan_dir)

        timestamp = datetime.now(tz=timezone.utc).isoformat()

        file=os.path.join(scan_dir, f"{scan_data.scan_type}_result_{timestamp}")
        
        params['subnet'] = probe_util.get_interface_subnet(interface=scan_data.interface)['network']
        params['export_file_name'] = file

        
        handler = action_map.get(scan_data.scan_type)
        if handler and params:
            code, output, error = await handler(**params)
        
        if code != 0:
            return Response(
                content=json.dumps({"error": error}),
                media_type="application/json",
                status_code=500
            )
        
        with open(file=f"{file}.xml") as xml_file:
            nmap_dict = xmltodict.parse(xml_file.read())

        nmap_json = json.dumps(nmap_dict)
        
        return Response(
            content=nmap_json,
            media_type="application/json",
            status_code=200
        )
        
    except Exception as e:
        logger.exception(f"Error running network scan: {e}")
        return Response(
            content=json.dumps({"error": str(e)}),
            media_type="application/json",
            status_code=500
        )