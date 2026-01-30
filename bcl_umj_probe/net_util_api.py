from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
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
import threading
#from CoreClient import CoreClient
from CoreClientv2 import CoreClient
import requests
import asyncio

class InitCall(BaseModel):
    umj_url: str 
    umj_usr: str
    umj_site: str
    umj_api_key: str
    prb_url: str
    prb_api_key: str
    prb_name: str

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))

prb_id, hstnm, probe_data = init_probe()
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

            # Only try to start if probe_data has an init URL
            if probe_data.get("umj_url_init"):
                try:
                    # Call the init endpoint to get a JWT cookie (use async httpx)
                    params = {"usr": probe_data.get("assigned_user")}
                    headers = {"X-UMJ-WFLW-API-KEY": probe_data.get("umj_api_key")}
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.get(probe_data.get("umj_url_init"), params=params, headers=headers)

                    if resp.status_code == 200:
                        umj_jwt_token = resp.cookies.get("access_token")
                        if umj_jwt_token:
                            # Build websocket url exactly how server expects it
                            ws_url = f"wss://{probe_data.get('umj_url')}/ws?prb=y&prb_id={probe_data.get('prb_id')}&unm={probe_data.get('assigned_user')}"

                            # Create CoreClient instance (expects run(stop_event) as async)
                            core_client = CoreClient(umj_url=probe_data.get("umj_url_init"),
                                                     umj_ws_url=ws_url,
                                                     umj_token=umj_jwt_token)

                            # create stop event and start async task
                            stop_event = asyncio.Event()
                            app.state.core_client_stop = stop_event
                            app.state.core_client = core_client
                            app.state.core_client_task = asyncio.create_task(core_client.run(stop_event))
                            logger.info("Started CoreClient task in FastAPI lifespan")
                        else:
                            logger.warning("Init returned no access_token cookie; skipping CoreClient startup")
                    else:
                        logger.warning("Init request returned status %s; skipping CoreClient startup", resp.status_code)
                except Exception as e:
                    logger.exception("Failed to start CoreClient during startup: %s", e)
            else:
                logger.info("No umj_url_init configured; not starting CoreClient")
        
        yield
        
        # signal stop and await task termination
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
    return {"status": "ok"}

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
    logger.info(probe_data)

    if await enrollment(payload=probe_data) != 200:
        return {"Error": "occurred during probe adoption"}, 400
    else:
        probe_info = await prb_db.get_all_data(match=f"prb-*")
        probe_info_dict = next(iter(probe_info.values()))
        probe_id = probe_info_dict.get('prb_id')

        umj_probe_data = {'url': init_data.prb_url,
                          'site': init_data.umj_site,
                          'name': init_data.prb_name,
                          'assigned_user': init_data.umj_usr,
                          'umj_url': init_data.umj_url,
                          'umj_url_init': init_url,
                          'umj_api_key': init_data.umj_api_key}

        if await prb_db.upload_db_data(id=probe_id, data=umj_probe_data) > 0:
            return 200
        else:
            return {"Error": "occurred during probe adoption"}, 400
