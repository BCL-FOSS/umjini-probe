from alert_base.Alert import Alert

class BotConnection(Alert):
    def __init__(self):
        super().__init__()
    
    async def mcp_exec(self, url: str, prb: str, usr: str, headers: dict, payload: dict = None):
        init_response = await self.make_request('g', f"{url}/v1/api/core/probe/init", headers)
        
        if init_response.status_code == 200:
            access_token = init_response.cookies.get("access_token")
        
        bot_response = await self.make_request('p', url=f"https://{url}/v1/api/core/probes/{prb}/exec?usr={usr}", headers=headers, payload=payload.get('payload'), cookies=access_token)

        return bot_response