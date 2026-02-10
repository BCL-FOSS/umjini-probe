from slack_sdk.web.async_client import AsyncWebClient
import os

class SlackAlert():
    def __init__(self, slack_bot_token: str = None, slack_channel_id: str = None):
        self.token = slack_bot_token
        self.channel_id = slack_channel_id
        self.client = AsyncWebClient(token=self.token)
        
    async def get_conversation(self):
        channels_data = {}
 
        convo_list = await self.client.conversations_list()
     
        for key, value in convo_list.data.items():
            if key == "channels":
                channels_data[value['name']] = value['id']

        return channels_data
    
    async def send_alert_message(self, message: str):
        response = await self.client.chat_postMessage(channel=self.channel_id, text=message)
        return response

    