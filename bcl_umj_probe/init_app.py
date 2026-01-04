from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader
import redis
from utils.network_utils.ProbeInfo import ProbeInfo
import logging
from passlib.hash import bcrypt
from utils.RedisDB import RedisDB
import uuid
import os
from onetimesecret import OneTimeSecretCli
from utils.EmailAlert import EmailAlert

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
probe_utils = ProbeInfo()

r = redis.Redis(host=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'), decode_responses=True)
pong = r.ping()
logger.info(f"Redis ping: {pong}")

email_alert = EmailAlert()

cli = OneTimeSecretCli(os.environ.get('OTS_USER'), os.environ.get('OTS_KEY'), os.environ.get('REGION'))

def init_probe():
    prb_id, hstnm = probe_utils.gen_probe_register_data()
    cursor, keys = r.scan(cursor=0, match=f'*prb-*')

    if not keys:
        probe_data=probe_utils.collect_local_stats(id=f"{prb_id}", hostname=hstnm)
        api_key = uuid.uuid4()

        link = cli.create_link(api_key,ttl=int(os.environ.get('OTS_TTL')))

        email_alert.send_email(
            subject="umjiniti Probe API Key Information",
            body=f"""
            Hello,

            Your umjiniti Probe has been initialized successfully.

            Please use the following link to retrieve your API key. Note that this link will expire in {os.environ.get('OTS_TTL')} seconds.

            API Key Retrieval Link: {link}

            Thank you,
            umjiniti Team
            """
        )

        probe_data['api_key'] = bcrypt.hash(str(api_key))

        str_hashmap = {str(k): str(v) for k, v in probe_data.items()}
        result = r.hset(prb_id, mapping=str_hashmap)
        logger.info(result)

        if isinstance(result, int):
            logger.info(probe_data)
            logger.info(probe_utils.get_ifaces())
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