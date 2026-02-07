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
from utils.Parsers import Parsers
from datetime import datetime, timedelta, timezone
from pathlib import Path
from utils.LogAlert import LogAlert

class InitCall(BaseModel):
    umj_url: str 
    umj_usr: str
    umj_site: str
    umj_api_key: str
    prb_url: str
    prb_api_key: str
    prb_name: str

class ExecCall(BaseModel):
    task: str
    params: dict = None

class ScanCall(BaseModel):
    scan_type: str
    interface: str
    params: dict = None

class TraceCall(BaseModel):
    trace_type: str
    target: str
    params: dict = None

class PerfCall(BaseModel):
    test_type: str
    params: dict = None

class PcapCall(BaseModel):
    capture_mode: str
    params: dict = None

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
prb_id, hstnm, probe_data = init_probe()
probe_util = ProbeInfo()
net_discovery = NetworkDiscovery()
net_test = NetworkTest()
parsers = Parsers()
pcap = PacketCapture()
log_alert = LogAlert()
action_map: dict[str, Callable[[dict], object]] = {
    "trcrt_dns": net_test.dnstraceroute,
    "trcrt": net_test.traceroute,
    "perf_srvr": net_test.iperf_server,
    "perf_clnt": net_test.iperf_client,
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
        
@api.post("/v1/api/probe/{probe_id}/exec", dependencies=[Depends(validate_api_key)])
async def execute_command(probe_id: str, cmd_data: ExecCall):
    try:
        await prb_db.connect_db()
        probe_info = await prb_db.get_all_data(match=f"{probe_id}")
        if not probe_info:
            return Response(
                content='{"error": "Probe not found"}',
                media_type="application/json",
                status_code=404
            )
        
        probe_info_dict = next(iter(probe_info.values()))
        
        if cmd_data.task != 'pcap_lcl':
            pcap.set_host(host=cmd_data.params['host'])
            pcap.set_credentials(user=cmd_data.params['usr'], password=cmd_data.params['pwd'])

            handler = action_map.get(cmd_data.task)
            parameters = cmd_data.params

            if handler and parameters:
                code, output, error = await handler(**parameters)
                if code != 0:
                    log_message=f""
                    log_message+=f"{code}\n\n"
                    log_message+=f"{output}\n\n"
                    log_message+=f"{error}"

                    timestamp = datetime.now(tz=timezone.utc).isoformat()
                    exec_name = f"{cmd_data.task}_result_{timestamp}"

                    await log_alert.write_log(log_name=exec_name, message=log_message)
                    cur_dir = os.getcwd()

                    scan_dir = os.path.join(cur_dir, "nmap_scans")

                    if not os.path.exists(scan_dir):
                        os.makedirs(scan_dir)

                    match cmd_data.task:
                        case str() as s if s.startswith("scan_"):
                            file=os.path.join(scan_dir, exec_name)

                            file_name = f"{file}.xml"

                            parameters['export_file_name'] = file_name
                            parameters['subnet'] = probe_util.get_interface_subnet(interface=cmd_data.params['interface'])['network']

                            with open(file=f"{file}.xml") as xml_file:
                                nmap_dict = xmltodict.parse(xml_file.read())
                                #nmap_json = json.dumps(nmap_dict)
                                result = parsers.parse_nmap_json(nmap_dict)

                        case str() as s if s.startswith("trcrt"):
                            hops = parsers.parse_traceroute_output(output, cmd_data.task)
        
                            result = {
                                "source": probe_id,
                                "destination": parameters['target'],
                                "trace_type": cmd_data.task,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "hops": hops
                                        }

                        case str() as s if s.startswith("test_"):
                            if cmd_data.task == 'test_srvr':
                                result = {
                                    "mode": "server",
                                    "server_ip": "0.0.0.0",
                                    "server_port": "7969",
                                    "status": "listening",
                                    "timestamp": datetime.now(timezone.utc).isoformat()
                                }
                            if cmd_data.task == 'test_clnt':
                                iperf_data = json.loads(output)
                                result = parsers.parse_iperf_output(iperf_data)

                        case str() as s if s.startswith("pcap_"):
                            packets = parsers.parse_pcap_summary(output)
        
                            result = {
                                "capture_mode": cmd_data.task,
                                "interface": cmd_data.params['interface'],
                                "packet_count": len(packets),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "packets": packets
                            }

                    task_result = {
                        'site': probe_info_dict.get('site'),
                        'task_output': json.dumps(result),
                        'prb_id': probe_info_dict.get('prb_id'),
                        'name': exec_name,
                        'prb_name': probe_info_dict.get('name'),
                        'task_type': f'{cmd_data.task}',
                        'timestamp': datetime.now(tz=timezone.utc).isoformat(),
                        'act': "prb_exec_rslt",
                        }
        
        if code != 0:
            return Response(
                content=json.dumps({"error": error}),
                media_type="application/json",
                status_code=500
            )
        
        return Response(
            content=json.dumps(task_result),
            media_type="application/json",
            status_code=200
        )
        
    except Exception as e:
        logger.exception(f"Error executing command: {e}")
        return Response(
            content=json.dumps({"error": str(e)}),
            media_type="application/json",
            status_code=500
        )