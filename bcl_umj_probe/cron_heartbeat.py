from utils.RedisDB import RedisDB
from utils.network_utils.ProbeInfo import ProbeInfo
import asyncio
import os
import logging
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
util_obj = ProbeInfo()

async def _make_http_request(cmd: str, url: str, payload: dict = {}, headers: dict = {}, cookies: str = ''):
    async with httpx.AsyncClient() as client:
        if cmd == 'p':
            client.cookies.set("access_token", value=cookies)
            return await client.post(url, json=payload, headers=headers)
        elif cmd == 'g':
            return await client.get(url, headers=headers)

async def heart_beat():
    probe_info = await prb_db.get_all_data(match=f"prb-*")
    probe_info_dict = next(iter(probe_info.values()))
    probe_id = probe_info_dict.get('prb_id')

    async def enrollment(payload: dict = {}):
        headers = {"X-UMJ-WFLW-API-KEY":  probe_info_dict.get("umj_api_key")}
        post_headers = {"X-UMJ-WFLW-API-KEY": probe_info_dict.get("umj_api_key"),
                        "Content-Type": "application/json"}

        resp_data = await _make_http_request(cmd="g", url=probe_info_dict.get("umj_url_init"), headers=headers)
        if resp_data.status_code == 200:
            access_token = resp_data.cookies.get("access_token")
            logger.info(access_token)
            await resp_data.aclose()

            enroll_rqst = await _make_http_request(
                cmd="p",
                url=probe_info_dict.get("umj_url"),
                headers=post_headers,
                cookies=access_token,
                payload=payload,
            )
            await enroll_rqst.aclose()
            return 200 if enroll_rqst.status_code == 200 else 400
        else:
            await resp_data.aclose()

        return None


        
if __name__ == "__main__":
    asyncio.run(heart_beat())