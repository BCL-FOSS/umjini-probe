import redis.asyncio as redis
import json
import logging
import os

class RedisDB:
   
    def __init__(self, hostname='', port=''):
        self.host_name=hostname
        self.port=port
        self.logger = logging.getLogger(__name__)
        
    async def connect_db(self):
        self.redis_conn = redis.from_url( 
                f"redis://{self.host_name}:{self.port}", 
                encoding="utf-8", decode_responses=True)
        if self.redis_conn is None:
            self.logger.info(f'Redis connection to {self.host_name} failed')
            return None
        else:
            self.logger.info(f'Redis connection to {self.host_name} succeeded.')

    async def ping_db(self):
        try:
            pong = await self.redis_conn.ping()
            self.logger.info(pong)
        except Exception as e:
            return {"DB Connection Error":str(e)}
        finally:
            await self.redis_conn.close()
    

    async def upload_db_data(self, id = '', data = {}):
        try: 

            str_hashmap = {str(k): str(v) for k, v in data.items()}
            result = await self.redis_conn.hset(id, mapping=str_hashmap)

            if result:
                return result 
            else:
                return None
            
        except Exception as e:
            return {"DB Upload Error":str(e)}
        finally:
            await self.redis_conn.close()

    async def get_all_data(self, match='*', cnfrm=False):
        try:
            all_data = {}
            cursor = b'0'  # Start the SCAN with cursor 0

            if cnfrm is True:
                cursor, keys = await self.redis_conn.scan(cursor=cursor, match=match)
                
                if keys:
                    return True
                else:
                    return False
                
            cursor, keys = await self.redis_conn.scan(cursor=cursor, match=match)
                
            for key in keys:
                # Retrieve hash data for each key
                hash_data = await self.redis_conn.hgetall(key)
                all_data[key] = {k: v for k, v in hash_data.items()}

            if all_data.items():
                return all_data
            else:
                return None
        except Exception as e:
            self.logger.info(f"Error retrieving data: {e}")
            return None
        finally:
            await self.redis_conn.close()
           
        
    async def get_obj_data(self, key=''):
        try:
            probe = await self.redis_conn.hgetall(key)

            if probe:
                return probe
            else:
                return None
                
        except Exception as e:
            return json.dumps({"error": str(e)})
        finally:
            await self.redis_conn.close()

    async def del_obj(self, key=''):
        try:
            probe = await self.redis_conn.delete(key)

            if probe:
                return probe
            else:
                return None
                
        except Exception as e:
            return json.dumps({"error": str(e)})
        finally:
            await self.redis_conn.close()

async def set_stream_msg(self, key: str, message: dict):
        try:
           
            result = await self.redis_conn.xadd(name=key, fields={"message": json.dumps(message)})

            return result if result is not None else None

        except Exception as e:
            return json.dumps({"error": str(e)})
        finally:
            await self.redis_conn.close()

async def get_stream_msgs(self, key: str, last_id: str = '0'):
        try:
            # Read last 100 messages
            messages = await self.redis_conn.xrange(name=key, min=last_id, max="+", count=100)

            return messages if messages is not None else None
            
        except Exception as e:
            return json.dumps({"error": str(e)})
        finally:
            await self.redis_conn.close()

async def del_stream_msgs(self, key: str):
        try:
            # Read last 100 messages
            messages = await self.redis_conn.xdel(name=key)

            return messages if messages is not None else None
            
        except Exception as e:
            return json.dumps({"error": str(e)})
        finally:
            await self.redis_conn.close()
        

 



        

