from alert_base.Alert import Alert
import json

class JiraSM(Alert):
    def __init__(self):
        super().__init__()

    def set_jira_connection_info(self, cloud_id: str, auth_email: str, auth_token: str):
        self.cloud_id = cloud_id
        self.auth_token = auth_token
        self.auth_email = auth_email

    async def send_alert(self, message: str, desc: str, note: str, source: str, entity: str, alias: str, priority: str, actions: list, extra_properties: dict):
        url = f"https://api.atlassian.com/jsm/ops/api/{self.cloud_id}/v1/alerts"

        auth = (self.auth_email, self.auth_token)

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        payload= json.dumps({
                            "message": message,
                            "responders": [
                                {"id": "4513b7ea-3b91-438f-b7e4-e3e54af9147c", "type": "team"},
                                {"id": "bb4d9938-c3c2-455d-aaab-727aa701c0d8", "type": "user"},
                                {"id": "aee8a0de-c80f-4515-a232-501c0bc9d715", "type": "escalation"},
                                {"id": "80564037-1984-4f38-b98e-8a1f662df552", "type": "schedule"}
                            ],
                            "visibleTo": [
                                {"id": "4513b7ea-3b91-438f-b7e4-e3e54af9147c", "type": "team"},
                                {"id": "bb4d9938-c3c2-455d-aaab-727aa701c0d8", "type": "user"}
                            ],
                            "note": note,
                            "alias": alias,
                            "entity": entity,
                            "source": source,
                            "tags": ["OverwriteQuietHours", "Critical"],
                            "actions": actions,
                            "description": desc,
                            "priority": priority,
                            "extraProperties": extra_properties
                        })

        result = await self.make_request(cmd='p', url=url, auth=auth, headers=headers, payload=payload)

        return result
    
    async def get_teams(self):
        url = f"https://api.atlassian.com/jsm/ops/api/{self.cloud_id}/v1/teams"

        auth = (self.auth_email, self.auth_token)

        headers = {
            "Accept": "application/json"
        }

        result = await self.make_request(cmd='g', url=url, auth=auth, headers=headers)

        return result
    
    async def get_schedules(self):
        url = f"https://api.atlassian.com/jsm/ops/api/{self.cloud_id}/v1/schedules"

        auth = (self.auth_email, self.auth_token)

        headers = {
            "Accept": "application/json"
        }

        result = await self.make_request(cmd='g', url=url, auth=auth, headers=headers)

        return result
    
    async def get_escalations(self, team_id: str):
        url = f"https://api.atlassian.com/jsm/ops/api/{self.cloud_id}/v1/teams/{team_id}/escalations"

        auth = (self.auth_email, self.auth_token)

        headers = {
            "Accept": "application/json"
        }

        result = await self.make_request(cmd='g', url=url, auth=auth, headers=headers)

        return result
    
