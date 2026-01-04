from fastapi import FastAPI, Depends
from fastapi_user_limiter.limiter import rate_limiter
from pydantic import BaseModel
from init_app import (
    validate_api_key,
    init_probe
)
import httpx
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.NetworkTest import NetworkTest
from typing import Callable
import logging
from net_util_mcp import mcp
import os

class InitCall(BaseModel):
    umj_url: str 
    umj_usr: str
    umj_site: str
    umj_api_key: str
    prb_url: str
    prb_api_key: str
    prb_name: str

class ToolCall(BaseModel):
    action: str 
    params: dict 

probe_utils = ProbeInfo()
net_test = NetworkTest()

prb_action_map: dict[str, Callable[[dict], object]] = {
    "prbdta": probe_utils.get_probe_data,
    "prbprc": probe_utils.get_processes_by_names,
    "prbprt": probe_utils.open_listening_ports,
    "prbifc": probe_utils.get_iface_ips,
}

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

prb_id, hstnm, probe_data = init_probe()
logger.info(f"Probe initialized id={prb_id}, hostname={hstnm}")

mcp_app = mcp.http_app(path="/mcp")
api = FastAPI(title='Network Util API', lifespan=mcp_app.lifespan)

async def _make_http_request(cmd: str, url: str, payload: dict = {}, headers: dict = {}, cookies: str = ''):
    async with httpx.AsyncClient() as client:
        if cmd == 'p':
            client.cookies.set("access_token", value=cookies)
            return await client.post(url, json=payload, headers=headers)
        elif cmd == 'g':
            return await client.get(url, headers=headers)
        
@api.get("/api/status", dependencies=[Depends(rate_limiter(2, 5))])
def status():
    return {"status": "ok"}

@api.post("/api/init", dependencies=[Depends(validate_api_key)])
async def init(init_data: InitCall):
    async def enrollment(payload: dict = {}):
        headers = {"X-UMJ-WFLW-API-KEY": init_data.umj_api_key}
        post_headers = {"X-UMJ-WFLW-API-KEY": init_data.umj_api_key,
                        "Content-Type": "application/json"}

        init_url = f"https://{init_data.umj_url}/init?usr={init_data.umj_usr}"
        logger.info(init_url)
        enroll_url = f"https://{init_data.umj_url}/enroll?usr={init_data.umj_usr}&site={init_data.umj_site}"
        logger.info(enroll_url)

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
    
    probe_data['url'] = init_data.prb_url
    probe_data['prb_api_key'] = init_data.prb_api_key
    probe_data['site'] = init_data.umj_site
    probe_data['name'] = init_data.prb_name
    logger.info(probe_data)

    if await enrollment(payload=probe_data) != 200:
        return {"Error": "occurred during probe adoption"}, 400
    else:
        return 200
        
@api.post("/api/probe", dependencies=[Depends(validate_api_key)])
def probe(tool_data: ToolCall):
    """Host system data"""
    handler = prb_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
        return handler(**tool_data.params)
