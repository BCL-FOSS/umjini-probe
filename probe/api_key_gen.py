from utils.RedisDB import RedisDB
from utils.network_utils.ProbeInfo import ProbeInfo
from uuid import uuid4
import asyncio
import argparse
import os
from passlib.hash import bcrypt
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
util_obj = ProbeInfo()

async def generate_api_key():
    
    await prb_db.connect_db()

    if await prb_db.get_all_data(match=f'prb-*', cnfrm=True) is False:
        logger.error("Failed to create probe API key.Restart the umjprobe container and try again...")
        return

    probe_data = await prb_db.get_all_data(match=f'prb-*')
    probe_data_dict = next(iter(probe_data.values()))
    probe_id = probe_data_dict.get('prb_id')

    api_key = str(uuid4())
    key_hash = bcrypt.hash(api_key)

    api_key_data = {"api_key": key_hash}

    if await prb_db.upload_db_data(id=probe_id, data=api_key_data) > 0:
        logger.info(f"API key generated for probe '{probe_id}':\n {api_key}")
        logger.info("Store this key securely as it will not be retrievable again in plaintext.")
    else:
        logger.error("API key gen failed...")
        
if __name__ == "__main__":
    asyncio.run(generate_api_key())