import httpx
import json

class Alert:
    def __init__(self):
        pass

    async def make_request(self, cmd:str, url: str, headers: dict, auth: tuple = None, payload: dict = None, cookies: str = None):

        async with httpx.AsyncClient() as client:
            match cmd:
                case 'pa':
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

                    return response

                case 'p':
                    client.cookies.set("access_token", value=cookies)
                    response = await client.post(
                        url,
                        headers=headers,
                        json=payload,
                    )  
            
            resp_data = response.json()

        if cmd == 'pa':
            return json.dumps(resp_data, sort_keys=True, indent=4, separators=(",", ": "))
        
        return json.dumps(resp_data)

    