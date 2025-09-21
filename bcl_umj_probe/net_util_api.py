from fastapi import FastAPI, Depends
from pydantic import BaseModel
from init_app import (
    validate_api_key,
    init_probe
)
import httpx
from contextlib import asynccontextmanager
from utils.network_utils.ProbeInfo import ProbeInfo
from typing import Callable
import logging
from net_util_mcp import mcp

class Init(BaseModel):
    api_key: str
    usr: str
    url: str
    site: str
    enroll: bool

class ToolCall(BaseModel):
    action: str 
    params: dict 

prb_id = None
hstnm = None
probe_data = None
probe_utils = ProbeInfo()

prb_action_map: dict[str, Callable[[dict], object]] = {
    "prbdta": probe_utils.get_probe_data,
    "prbprc": probe_utils.get_processes_by_names,
    "prbprt": probe_utils.open_listening_ports,
    "prbifc": probe_utils.get_iface_ips,
}

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global prb_id, hstnm, probe_data
    prb_id, hstnm, probe_data = init_probe()
    logger.info(f"Probe initialized id={prb_id}, hostname={hstnm}")
    yield

api = FastAPI(title='Network Util API', lifespan=lifespan)
mcp_app = mcp.http_app(path="/mcp")

async def _make_http_request(cmd: str, url: str, payload: dict = {}, headers: dict = {}, cookies: str = ''):
    async with httpx.AsyncClient() as client:
        if cmd == 'p':
            client.cookies.set("access_token", value=cookies)
            return await client.post(url, json=payload, headers=headers)
        elif cmd == 'g':
            return await client.get(url, headers=headers)

@api.get("/api/status", dependencies=[Depends(validate_api_key)])
def status():
    return {"status": "ok"}

@api.post("/api/init", dependencies=[Depends(validate_api_key)])
async def init(init_data: Init):
    async def enrollment(payload: dict = {}):
        logger.info(init_data)
        headers = {"X-UMJ-WFLW-API-KEY": init_data.api_key}
        post_headers = {"X-UMJ-WFLW-API-KEY": init_data.api_key,
                        "Content-Type": "application/json"}

        init_url = f"https://{init_data.url}/init?usr={init_data.usr}"
        enroll_url = f"https://{init_data.url}/enroll?usr={init_data.usr}&site={init_data.site}"

        resp_data = await _make_http_request(cmd="g", url=init_url, headers=headers)
        if resp_data.status_code == 200:
            access_token = resp_data.cookies.get("access_token")
            logger.info(access_token)

            enroll_rqst = await _make_http_request(
                cmd="p",
                url=enroll_url,
                headers=post_headers,
                cookies=access_token,
                payload=payload,
            )
            return 200 if enroll_rqst.status_code == 200 else 400

    if init_data.enroll is False or not (init_data.api_key and init_data.usr and init_data.url and init_data.site):
        return 400

    if await enrollment(payload=probe_data) != 200:
        return {"Error": "occurred during probe adoption"}, 400
    else:
        return 200
        
@api.post("/api/probe", dependencies=[Depends(validate_api_key)])
def prb(tool_data: ToolCall):
    """Host system data"""
    handler = prb_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
        return handler(**tool_data.params)
