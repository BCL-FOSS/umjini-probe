from utils.alerts_utils.alert_base.Alert import Alert

class BotConnection(Alert):
    def __init__(self):
        super().__init__()
    
    async def send_bot_message(self, url: str, headers: dict, payload: dict = None):

        init_response = await self.make_request('g', f"{url}/v1/api/core/probe/init", headers)

        if init_response.status_code == 200:
            access_token = init_response.cookies.get("access_token")
        
        bot_response = await self.make_request('p', url=f"{url}/v1/api/core/bots/{payload.get('tool')}/exec?usr={payload.get('usr')}", headers=headers, payload=payload, cookies=access_token)

        if bot_response.status_code == 200:
            return bot_response
        else:
            return None