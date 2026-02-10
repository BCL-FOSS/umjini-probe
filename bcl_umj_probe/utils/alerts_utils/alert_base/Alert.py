import httpx
import json

class Alert:
    def __init__(self):
        pass

    async def make_request(self, cmd:str, url: str, headers: dict, auth: tuple = None, payload: dict = None):

        async with httpx.AsyncClient() as client:
            match cmd:
                case 'p':
                    response = await client.post(
                        url,
                        headers=headers,
                        auth=auth,
                        json=payload
                    )
                case 'g':
                    response = await client.get(
                        url,
                        headers=headers,
                        auth=auth
                    )
            
            resp_data = response.json()

            await response.aclose()

        return json.dumps(resp_data, sort_keys=True, indent=4, separators=(",", ": "))

    