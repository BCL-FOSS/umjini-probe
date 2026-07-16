import asyncio
import websockets
import os
from websockets.sync.client import ClientConnection
from websockets.sync.client import connect
import os
import json
from typing import Optional
#from websockets import connect
import asyncio
from datetime import datetime, timezone
from init_app import log_alert, slack_alert, jira_alert, email_alert, prb_db, logger, action_map
from auto_scripts.script_base.base import run_task, parse_scan_results

class CoreClient:
    def __init__(self, umj_ws_url: str):
        self.logger = logger
        self.umj_ws = umj_ws_url
        self.prb_db = prb_db
        
    def stop(self):
            if getattr(self, "_stop_event", None) is not None:
                try:
                    self._stop_event.set()
                except Exception:
                    pass
            self._internal_stop = True

    async def connect_with_backoff(self, ws_url: str, stop_event: Optional[asyncio.Event] = None):
        await self.prb_db.connect_db()
        probe_data = await self.prb_db.get_all_data(match='prb:*')
        probe_data_dict = next(iter(probe_data.values()))

        if stop_event is None:
            stop_event = asyncio.Event()
        self._stop_event = stop_event
        self._internal_stop = False

        self.logger.info("CoreClient: entering connect_with_backoff loop")

        async with connect(uri=ws_url) as websocket:
            self.logger.info(f"Connected to {ws_url}")

            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                try:
                    if stop_event.is_set() or getattr(self, "_internal_stop", False):
                        self.logger.info("Stop requested, exiting connect loop after clean disconnect")
                        break

                    await self.interact(websocket, probe_obj=probe_data_dict, stop_event=stop_event)
                
                    await asyncio.wait_for(stop_event.wait(), timeout=0.5)

                except websockets.exceptions.ConnectionClosed as e:
                    self.logger.error(f"WebSocket connection closed: {e}")
                except websockets.exceptions.InvalidHandshake as ih:
                    self.logger.error(f"WebSocket invalid handshake: {ih}")
                except websockets.exceptions.WebSocketException as we:
                    self.logger.error(f"WebSocket exception: {we}")
                except asyncio.CancelledError:
                    self.logger.info("connect_with_backoff cancelled")
                except Exception as e:
                    self.logger.exception(f"Unexpected error connecting websocket: {e}")

        self.logger.info("CoreClient: exiting connect_with_backoff")

    async def interact(self, ws: ClientConnection, probe_obj: dict, stop_event: Optional[asyncio.Event] = None):
        if stop_event is None:
            stop_event = asyncio.Event()

        async def _alerts():
            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                raw_message = await ws.recv()
                core_act_data = json.loads(raw_message)
                self.logger.info(f"Received CoreClient message: {core_act_data}.")
                probe_id = core_act_data['prb_id']
                if (probe_id and probe_id == probe_obj.get('prb_id')) and core_act_data['alerts']['tool'] in action_map :
                    match core_act_data['alerts']['tool']:
                         case 'slack':
                            slack_alert.set_slack_connection_info(slack_bot_token=os.environ.get('slack-token'), slack_channel_id=os.environ.get('slack-channel'))
                         case 'jira':
                            jira_alert.set_jira_connection_info(cloud_id=os.environ.get('jira-cloud-id'), auth_email=os.environ.get('jira-auth-email'), auth_token=os.environ.get('jira-auth-token'))
                         case 'email':
                            email_alert.set_brevo_api_key(os.environ.get('brevo-api-key'))
                            html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                                    <p>Task Alert</p>
                                    <p>Probe: {probe_obj.get('name')}</p>
                                    <p>Site: {probe_obj.get('site')}</p>
                                    <p>Action: {core_act_data['task_type']}</p>
                                    <p>Result: {core_act_data['llm_output']}</p>
                                    </div>"""
                        
                            params = {
                                    'sender': {'name': f'Probe: {probe_obj.get("name")}', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                    'to': [{"name": os.environ.get('BREVO_RECIPIENT_NAME'), "email": os.environ.get('BREVO_RECIPIENT_EMAIL')}],
                                    'subject': f"Task Alert: {core_act_data['task_type']} executed on probe {probe_obj.get('name')}",
                                    'html_content': html_snippet
                                }

                    code, output, error, _ = await run_task(action=core_act_data['alerts']['tool'], params=params)

                    if code != 0:
                        logger.info(f"{code}\n{error}\n{output}")

                    task_name = f"alert_{core_act_data['flow_name']}_{datetime.now(tz=timezone.utc).isoformat()}" if 'flow_name' in core_act_data else f"alert_{core_act_data['task_type']}_{datetime.now(tz=timezone.utc).isoformat()}"

                    task_result = {
                        'site': probe_obj.get('site'),
                        'task_output': core_act_data['llm_output'],
                        'prb_id': probe_obj.get('prb_id'),
                        'assigned_user': probe_obj.get('assigned_user'),
                        'name': task_name,
                        'prb_name': probe_obj.get('name'),
                        'task_type': f'{core_act_data["task"]}',
                        'timestamp': datetime.now(tz=timezone.utc).isoformat(),
                        'act': "task_rslt",
                    }
                    await ws.send(json.dumps(task_result))

        async def _heartbeat():
            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                ping = {
                    "sess_id": probe_obj.get('prb_id'),
                    "site": probe_obj.get('site'),
                    "act": "heart_beat"
                }
                try:
                    await ws.send(json.dumps(ping))
                except websockets.ConnectionClosed:
                    self.logger.warning("Heartbeat: connection closed")
                    break
                except asyncio.CancelledError:
                    break
                except Exception:
                    self.logger.exception("Heartbeat: failed to send ping")
                    break
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=30.0)
                    break
                except asyncio.TimeoutError:
                    continue

        async def _mapper():
            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                code, output, error, file_name = await run_task(action="scan_map")

                result = await parse_scan_results(action="scan_map", code=code, file_name=file_name, probe_data_dict=probe_obj, params_dict={}, output=output)

                log_message=f""
                log_message+=f"{code}\n\n"
                log_message+=f"{output}\n\n"
                log_message+=f"{error}"
                await log_alert.write_log(log_name=f"network_map_{datetime.now(tz=timezone.utc).isoformat()}", message=log_message)

                network_map_result = {
                    "prb_id": probe_obj.get('prb_id'),
                    "site": probe_obj.get('site'),
                    "map_type": "full_scan",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "map": result,
                    "act": "prb_netmap_rslt"
                }

                try:
                    await ws.send(json.dumps(network_map_result))
                except websockets.ConnectionClosed:
                    self.logger.warning("Network mapping: connection closed")
                    break
                except asyncio.CancelledError:
                    break
                except Exception:
                    self.logger.exception("Network mapping: failed to send result")
                    break
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=300.0)
                    break
                except asyncio.TimeoutError:
                    continue

        alert_task = asyncio.create_task(_alerts())
        hb_task = asyncio.create_task(_heartbeat())
        map_task = asyncio.create_task(_mapper())

        done, pending = await asyncio.wait([alert_task, hb_task, map_task], return_when=asyncio.FIRST_COMPLETED)

        for t in pending:
            t.cancel()
            try:
                await t
            except Exception:
                pass
        self.logger.debug("Interact finished (alerts/heartbeat/mapper)")

    async def run(self, stop_event: Optional[asyncio.Event] = None):
        self.logger.info("CoreClient.run starting")
        if stop_event is None:
            stop_event = asyncio.Event()
        self._stop_event = stop_event
        self._internal_stop = False

        try:
            await self.connect_with_backoff(ws_url=self.umj_ws, stop_event=stop_event)
        except asyncio.CancelledError:
            self.logger.info("CoreClient.run cancelled")
            raise
        except Exception:
            self.logger.exception("Unhandled exception in CoreClient.run")
        finally:
            self.logger.info("CoreClient.run finished")