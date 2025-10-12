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
from dotenv import load_dotenv

class ToolCall(BaseModel):
    action: str 
    params: dict 

load_dotenv() 
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

@api.get("/api/init", dependencies=[Depends(validate_api_key)])
async def init():
    async def enrollment(payload: dict = {}):
        headers = {"X-UMJ-WFLW-API-KEY": os.environ.get('X-UMJ-WFLW-API-KEY')}
        post_headers = {"X-UMJ-WFLW-API-KEY": os.environ.get('X-UMJ-WFLW-API-KEY'),
                        "Content-Type": "application/json"}

        init_url = f"https://{os.environ.get('UMJ-URL')}/init?usr={os.environ.get('UMJ-USR')}"
        enroll_url = f"https://{os.environ.get('UMJ-URL')}/enroll?usr={os.environ.get('UMJ-USR')}&site={os.environ.get('UMJ-SITE')}"

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
    
    probe_data['url'] = os.environ.get('UMJ-URL')
    probe_data['prb_api_key'] = os.environ.get('PRB-API-KEY')
    probe_data['site'] = os.environ.get('UMJ-SITE')
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
