from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader
import redis
from utils.network_utils.ProbeInfo import ProbeInfo
import logging
from passlib.hash import bcrypt
import os

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logging.getLogger("fakeredis").setLevel(logging.WARNING)
logging.getLogger("docket.worker").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)

probe_utils = ProbeInfo()

r = redis.Redis(host=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'), decode_responses=True)
pong = r.ping()
logger.info(f"Redis ping: {pong}")

def init_probe():
    prb_id, hstnm = probe_utils.gen_probe_register_data()
    cursor, keys = r.scan(cursor=0, match=f'*prb-*')

    if not keys:
        probe_data=probe_utils.collect_local_stats(id=f"{prb_id}", hostname=hstnm)
        host_interfaces = probe_utils.get_ifaces()
        probe_data['iface_list'] = host_interfaces
        logger.info(host_interfaces)

        str_hashmap = {str(k): str(v) for k, v in probe_data.items()}
        result = r.hset(prb_id, mapping=str_hashmap)
        logger.info(result)

        if isinstance(result, int):
            return prb_id, hstnm, probe_data

    if keys:
        for redis_key in keys:
            hash_data = r.hgetall(redis_key)
            logger.info(hash_data)
            prb_id = hash_data.get('prb_id')
            probe_data = hash_data
        return prb_id, hstnm, probe_data
        

def validate_api_key(key: str = Depends(api_key_header)):
    _, hostname = probe_utils.gen_probe_register_data()
    cursor, keys = r.scan(cursor=0, match=f'*prb-*')

    if keys:
        for redis_key in keys:
            hash_data = r.hgetall(redis_key)
            logger.info(hash_data)
            stored_api_key = hash_data.get("api_key")
            logger.info(stored_api_key)

            if not stored_api_key:
                raise

            if bcrypt.verify(key, stored_api_key):
                return 200
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing API key"
                )