import asyncio
import websockets
import os
from websockets import ClientConnection, ConnectionClosed
import os
import logging
from utils.RedisDB import RedisDB
import json
from websockets import ConnectionClosed
from typing import Optional
from websockets.asyncio.client import connect
import asyncio
import xmltodict
from datetime import datetime, timezone
from init_app import action_map, pcap, log_alert, parsers, net_discovery, slack_alert, jira_alert, email_alert, probe_util, cron


class CoreClient:
    def __init__(self, umj_ws_url: str):
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.logger = logging.getLogger(__name__)
        self.umj_ws = umj_ws_url
        self.prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
        self.cur_dir = os.getcwd()
        self.scan_dir = os.path.join(self.cur_dir, "nmap_scans")
        if not os.path.exists(self.scan_dir):
            os.makedirs(self.scan_dir)
        
    def stop(self):
            # If external stop_event exists, set it
            if getattr(self, "_stop_event", None) is not None:
                try:
                    self._stop_event.set()
                except Exception:
                    pass
            # Set internal flag
            self._internal_stop = True

    async def connect_with_backoff(self, ws_url: str, stop_event: Optional[asyncio.Event] = None):
        await self.prb_db.connect_db()
        probe_data = await self.prb_db.get_all_data(match='prb:*')
        probe_data_dict = next(iter(probe_data.values()))

        if stop_event is None:
            stop_event = asyncio.Event()
        # store reference for stop() to set if called
        self._stop_event = stop_event
        self._internal_stop = False

        self.logger.info("CoreClient: entering connect_with_backoff loop")

        async with connect(uri=ws_url) as websocket:
            self.logger.info(f"Connected to {ws_url}")

            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                try:
                    # If stop requested, break the outer loop
                    if stop_event.is_set() or getattr(self, "_internal_stop", False):
                        self.logger.info("Stop requested, exiting connect loop after clean disconnect")
                        break

                    # Run interaction until it returns (connection closed or stop requested).
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

        async def _receive():
            
            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                
                raw_message = await ws.recv()
                core_act_data = json.loads(raw_message)
                self.logger.info(f"Received CoreClient message: {core_act_data}.")

                probe_id = core_act_data['prb_id']
                if probe_id and probe_id == probe_obj.get('prb_id'):
                    match core_act_data['oper']:
                        case 'init_task':

                            job1 = None
                            ws_url = f"wss://{probe_obj.get('umj_url')}/v1/api/core/channels/probe/heartbeat/{probe_obj.get('prb_id')}"
                            cwd = os.getcwd()

                            if core_act_data['auto_type'] == 'task':
                                if 'prms' in core_act_data and core_act_data['prms']:
                                    params = core_act_data['prms']
                                script_path = os.path.join(cwd, 'task_auto.py')
                                job_comment=f"auto_task_{probe_obj.get('prb_id')}_task_{core_act_data['task']}"
                                job1=cron.new(command=f"python3 {script_path} -a {core_act_data['task']} -p '{json.dumps(params)}' -w {ws_url} -pdta '{json.dumps(probe_obj)}' -n {job_comment} -llm {core_act_data.get('llm')} -llmdta '{json.dumps(core_act_data.get('llm_data'))}' -alert '{json.dumps(core_act_data.get('alert_type'))}'", comment=job_comment)

                            if core_act_data['auto_type'] == 'flow':
                                script_path = os.path.join(cwd, 'flow_auto.py')
                                job_comment=f"auto_task_{probe_obj.get('prb_id')}_flow_{core_act_data['flow_id']}"
                                job1=cron.new(command=f"python3 {script_path} -f {core_act_data['flow']} -w {ws_url} -pdta '{json.dumps(probe_obj)}' -n {core_act_data['flow_name']}", comment=job_comment)

                            if 'minutes' in core_act_data and core_act_data['minutes']:
                                    minutes_range = str(core_act_data['minutes']).split(",")
                                    if isinstance(minutes_range, list):
                                        if len(minutes_range) == 3:
                                            job1.minute.during(minutes_range[0], minutes_range[1]).every(minutes_range[2])
                                        elif len(minutes_range) == 2:
                                            job1.minute.during(minutes_range[0], minutes_range[1])
                                        elif len(minutes_range) == 1:
                                            job1.minute.every(minutes_range[0])

                            if 'hours' in core_act_data and core_act_data['hours']:
                                    hours_range = str(core_act_data['hours']).split(",")
                                    if isinstance(hours_range, list):
                                        if len(hours_range) == 3:
                                            job1.hour.during(hours_range[0], hours_range[1]).every(hours_range[2])
                                        elif len(hours_range) == 2:
                                            job1.hour.during(hours_range[0], hours_range[1])
                                        elif len(hours_range) == 1:
                                            job1.hour.every(hours_range[0])

                            if 'dom' in core_act_data and core_act_data['dom']:
                                    dom_range = str(core_act_data['dom']).split(",")
                                    if isinstance(dom_range, list):
                                        if len(dom_range) == 3:
                                            job1.dom.during(dom_range[0], dom_range[1]).every(dom_range[2])
                                        elif len(dom_range) == 2:
                                            job1.dom.during(dom_range[0], dom_range[1])
                                        elif len(dom_range) == 1:
                                            job1.dom.every(dom_range[0])

                            if 'days' in core_act_data and core_act_data['days']:
                                    days_range = str(core_act_data['days']).split(",")
                                    if isinstance(days_range, list):
                                        job1.dow.on(days_range)

                            if 'months' in core_act_data and core_act_data['months']:
                                    months_range = str(core_act_data['months']).split(",")
                                    if isinstance(months_range, list):
                                        if len(months_range) == 3:
                                            job1.month.during(months_range[0], months_range[1]).every(months_range[2])
                                        elif len(months_range) == 2:
                                            job1.month.during(months_range[0], months_range[1])
                                        elif len(months_range) == 1:
                                            job1.month.every(months_range[0])

                            if await asyncio.to_thread(job1.is_valid()):
                                    await asyncio.to_thread(cron.write())
                                    await asyncio.sleep(1)
                                    self.logger.info(f"Cron job added: {job1}")
                                    await ws.send(json.dumps({
                                        'site': probe_obj.get('site'),
                                        'task_output': f"{core_act_data['auto_type']} cron job added to {probe_obj.get('name')} at site: {probe_obj.get('site')}.",
                                        'prb_id': probe_obj.get('prb_id'),
                                        'prb_name': probe_obj.get('name'),
                                        'job_type': core_act_data['auto_type'] if core_act_data['auto_type'] == 'flow' else f'{core_act_data['task']}',
                                        'job_name': f'cron_job_{job_comment}',
                                        'act': "prb_task_cnfrm",
                                        'comment': job_comment,
                                        'enabled': 'enabled',
                                        'storage_opt': 'new',
                                        'user_id': core_act_data['user_id']
                                    }))
                            else:
                                    self.logger.error("Invalid cron job, not writing to crontab.")
                           
                        case 'disable_task':
                            job = cron.find_comment(comment=core_act_data['comment'])
                            #iter = cron.find_comment(re.compile(' or \w'))
                            job.enable(False)
                            await asyncio.to_thread(cron.write())
                            await asyncio.sleep(1)
                            core_act_data['storage_opt'] = 'updt'
                            core_act_data['act'] = 'prb_task_cnfrm'
                            core_act_data['task_output'] = f"Cron job '{core_act_data['comment']}' disabled."
                            await ws.send(json.dumps(core_act_data))
                        case 'enable_task':
                            job = cron.find_comment(comment=core_act_data['comment'])
                            #iter = cron.find_comment(re.compile(' or \w'))
                            job.enable()
                            await asyncio.to_thread(cron.write())
                            await asyncio.sleep(1)
                            core_act_data['storage_opt'] = 'updt'
                            core_act_data['act'] = 'prb_task_cnfrm'
                            core_act_data['task_output'] = f"Cron job '{core_act_data['comment']}' enabled."
                            await ws.send(json.dumps(core_act_data))
                        case 'rm_task':
                            job = cron.find_comment(comment=core_act_data['comment'])
                            #iter = cron.find_comment(re.compile(' or \w'))
                            cron.remove( job )
                            await asyncio.to_thread(cron.write())
                            await asyncio.sleep(1)
                            core_act_data['act'] = 'prb_task_cnfrm'
                            core_act_data['task_output'] = f"Cron job '{core_act_data['comment']}' deleted."
                            core_act_data['storage_opt'] = 'del'
                            await ws.send(json.dumps(core_act_data))
                        case 'rm_all_tasks':
                            cron.remove_all()
                            await asyncio.to_thread(cron.write())
                            await asyncio.sleep(1)
                            core_act_data['act'] = 'prb_task_cnfrm'
                            core_act_data['task_output'] = f"All cron jobs deleted."
                            await ws.send(json.dumps(core_act_data))
                        case 'resch_task':
                            job = cron.find_comment(comment=core_act_data['comment'])
                            if job:
                                if 'minutes' in core_act_data and core_act_data['minutes']:
                                    minutes_range = str(core_act_data['minutes']).split(",")
                                    if isinstance(minutes_range, list):
                                        if len(minutes_range) == 3:
                                            job.minute.during(minutes_range[0], minutes_range[1]).every(minutes_range[2])
                                        elif len(minutes_range) == 2:
                                            job.minute.during(minutes_range[0], minutes_range[1])
                                        elif len(minutes_range) == 1:
                                            job.minute.every(minutes_range[0])

                                if 'hours' in core_act_data and core_act_data['hours']:
                                    hours_range = str(core_act_data['hours']).split(",")
                                    if isinstance(hours_range, list):
                                        if len(hours_range) == 3:
                                            job.hour.during(hours_range[0], hours_range[1]).every(hours_range[2])
                                        elif len(hours_range) == 2:
                                            job.hour.during(hours_range[0], hours_range[1])
                                        elif len(hours_range) == 1:
                                            job.hour.every(hours_range[0])

                                if 'dom' in core_act_data and core_act_data['dom']:
                                    dom_range = str(core_act_data['dom']).split(",")
                                    if isinstance(dom_range, list):
                                        if len(dom_range) == 3:
                                            job.dom.during(dom_range[0], dom_range[1]).every(dom_range[2])
                                        elif len(dom_range) == 2:
                                            job.dom.during(dom_range[0], dom_range[1])
                                        elif len(dom_range) == 1:
                                            job.dom.every(dom_range[0])

                                if 'days' in core_act_data and core_act_data['days']:
                                    days_range = str(core_act_data['days']).split(",")
                                    if isinstance(days_range, list):
                                        job.dow.on(days_range)

                                if 'months' in core_act_data and core_act_data['months']:
                                    months_range = str(core_act_data['months']).split(",")
                                    if isinstance(months_range, list):
                                        if len(months_range) == 3:
                                            job.month.during(months_range[0], months_range[1]).every(months_range[2])
                                        elif len(months_range) == 2:
                                            job.month.during(months_range[0], months_range[1])
                                        elif len(months_range) == 1:
                                            job.month.every(months_range[0])
                                
                                if await asyncio.to_thread(job.is_valid()):
                                    await asyncio.to_thread(cron.write())
                                    await asyncio.sleep(1)
                                    self.logger.info(f"Cron job rescheduled: {job}")
                                    core_act_data['enabled'] = 'enabled' if job.is_enabled() else 'disabled'
                                    core_act_data['storage_opt'] = 'updt'
                                    core_act_data['act'] = 'prb_task_cnfrm'
                                    core_act_data['task_output'] = f"Cron job '{core_act_data['comment']}' rescheduled."
                                    await ws.send(json.dumps(core_act_data))
                        case 'exec':    
                            if core_act_data['task'] == 'pcap_tux' or core_act_data['task'] == 'pcap_win':
                                pcap.set_host(host=core_act_data['prms']['host'])
                                pcap.set_credentials(user=core_act_data['prms']['usr'], password=core_act_data['prms']['pwd'])

                            handler = action_map.get(core_act_data['task'])
                            parameters = core_act_data['prms']

                            if core_act_data['task'].startswith("scan_"):
                                timestamp = datetime.now(tz=timezone.utc).isoformat()
                                exec_name = f"{core_act_data['task']}_result_{timestamp}"
                                file=os.path.join(self.scan_dir, exec_name)
                                file_name = f"{file}.xml"
                                net_discovery.set_output_file(file_name=file_name)

                                if 'interface' not in parameters or not parameters['interface']:
                                    net_discovery.set_interface(probe_util.get_ifaces()[0])
                                    parameters['subnet'] = probe_util.get_interface_subnet(interface=probe_util.get_ifaces()[0])['network']

                                if 'subnet' not in parameters or not parameters['subnet'] and parameters['interface']:
                                    net_discovery.set_interface(parameters['interface'])
                                    parameters['subnet'] = probe_util.get_interface_subnet(interface=parameters['interface'])['network']

                            if handler and parameters:
                                code, output, error = await handler(**parameters)

                            if code == 0:
                                log_message=f""
                                log_message+=f"{code}\n\n"
                                log_message+=f"{output}\n\n"
                                log_message+=f"{error}"

                                await log_alert.write_log(log_name=f"{core_act_data['task']}_result_{timestamp}", message=log_message)

                                match core_act_data['task']:
                                    case str() as s if s.startswith("scan_"):
                                        
                                        with open(file=f"{file_name}") as xml_file:
                                            nmap_dict = xmltodict.parse(xml_file.read())

                                        #nmap_json = json.dumps(nmap_dict)
                                        result = parsers.parse_nmap_json(nmap_dict)

                                    case str() as s if s.startswith("trcrt"):
                                        hops = parsers.parse_traceroute_output(output, core_act_data['task'])
        
                                        result = {
                                            "source": probe_id,
                                            "destination": parameters['target'],
                                            "trace_type": core_act_data['task'],
                                            "timestamp": datetime.now(timezone.utc).isoformat(),
                                            "hops": hops
                                        }

                                    case str() as s if s.startswith("test_"):
                                        if core_act_data['task'] == 'test_srvr':
                                            result = {
                                                "mode": "server",
                                                "server_ip": "0.0.0.0",
                                                "server_port": "7969",
                                                "status": "listening",
                                                "timestamp": datetime.now(timezone.utc).isoformat()
                                            }

                                        if core_act_data['task'] == 'test_clnt':
                                            iperf_data = json.loads(output)
                                            result = parsers.parse_iperf_output(iperf_data)

                                    case str() as s if s.startswith("pcap_"):
                                        packets = parsers.parse_pcap_summary(output)
        
                                        result = {
                                            "capture_mode": core_act_data['task'],
                                            "interface": core_act_data['interface'],
                                            "packet_count": len(packets),
                                            "timestamp": datetime.now(timezone.utc).isoformat(),
                                            "packets": packets
                                        }

                                task_result = {
                                        'site': probe_obj.get('site'),
                                        'task_output': result,
                                        'prb_id': probe_obj.get('prb_id'),
                                        'assigned_user': probe_obj.get('assigned_user'),
                                        'name': exec_name,
                                        'prb_name': probe_obj.get('name'),
                                        'task_type': f'{core_act_data["task"]}',
                                        'timestamp': datetime.now(tz=timezone.utc).isoformat(),
                                        'user_id': core_act_data['user_id'],
                                        'act': "prb_task_rslt",
                                    }
                                await ws.send(json.dumps(task_result))

                        case 'alert':
                            if core_act_data['alerts']['tool'] == 'slack':
                                slack_alert.set_slack_connection_info(slack_bot_token=os.environ.get('slack-token'), slack_channel_id=os.environ.get('slack-channel'))

                            if core_act_data['alerts']['tool'] == 'jira':
                                jira_alert.set_jira_connection_info(cloud_id=os.environ.get('jira-cloud-id'), auth_email=os.environ.get('jira-auth-email'), auth_token=os.environ.get('jira-auth-token'))

                            if core_act_data['alerts']['tool'] == 'email':
                                email_alert.set_brevo_api_key(os.environ.get('brevo-api-key'))
                                html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                                    <p>Task Alert</p>
                                    <p>Probe: {probe_obj.get('name')}</p>
                                    <p>Site: {probe_obj.get('site')}</p>
                                    <p>Action: {core_act_data['task_type']}</p>
                                    <p>Result: {core_act_data['llm_output']}</p>
                                    </div>"""
                                send_result = asyncio.to_thread(
                                    email_alert.send_transactional_email, 
                                    sender={'name': f'Probe: {probe_obj.get("name")}', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                    to=[{"name": os.environ.get('BREVO_RECIPIENT_NAME'), "email": os.environ.get('BREVO_RECIPIENT_EMAIL')}],
                                    subject=f"Task Alert: {core_act_data['task_type']} executed on probe {probe_obj.get('name')}",
                                    html_content=html_snippet
                                    )
                                self.logger.info(type(send_result))

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
                                        'act': "prb_task_rslt",
                                    }
                            await ws.send(json.dumps(task_result))

                            
                        case _:
                            self.logger.warning(f"Unknown operation received: {core_act_data['oper']}")

        async def _heartbeat():
            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                ping = {
                    "sess_id": probe_obj.get('prb_id'),
                    "site": probe_obj.get('site'),
                    "act": "heart_beat"
                }
                try:
                    await ws.send(json.dumps(ping))
                except ConnectionClosed:
                    self.logger.warning("Heartbeat: connection closed")
                    break
                except asyncio.CancelledError:
                    break
                except Exception:
                    self.logger.exception("Heartbeat: failed to send ping")
                    break
                # Heartbeat interval 30s
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=30.0)
                    # If stop_event set, break out
                    break
                except asyncio.TimeoutError:
                    continue

        async def _network_mapper():
            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                timestamp = datetime.now(tz=timezone.utc).isoformat()
                exec_name = f"net_mapper_result_{timestamp}"
                file=os.path.join(self.scan_dir, exec_name)
                file_name = f"{file}.xml"
                net_discovery.set_output_file(file_name=file_name)
                net_discovery.set_interface(probe_util.get_ifaces()[0])
                subnet = probe_util.get_interface_subnet(interface=probe_util.get_ifaces()[0])['network']

                handler = action_map.get("scan_full")
                parameters = {'subnet': subnet}
                code, output, error = await handler(**parameters)
                if code != 0:
                    self.logger.error(f"Network mapping failed with code {code}: {error}")
                else:
                    log_message=f""
                    log_message+=f"{code}\n\n"
                    log_message+=f"{output}\n\n"
                    log_message+=f"{error}"
                    await log_alert.write_log(log_name=f"network_map_{datetime.now(tz=timezone.utc).isoformat()}", message=log_message)
                    with open(file=f"network_map_{datetime.now(tz=timezone.utc).isoformat()}.xml") as xml_file:
                        nmap_dict = xmltodict.parse(xml_file.read())
                    result = parsers.parse_nmap_json(nmap_dict)
                    network_map_result = {
                            "prb_id": probe_obj.get('prb_id'),
                            "destination": "local_network",
                            "subnet": subnet,
                            "map_type": "full_scan",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "map": result,
                            "act": "prb_netmap_rslt"
                        }

                    try:
                        await ws.send(json.dumps(network_map_result))
                    except ConnectionClosed:
                        self.logger.warning("Network mapping: connection closed")
                        break
                    except asyncio.CancelledError:
                        break
                    except Exception:
                        self.logger.exception("Network mapping: failed to send result")
                        break
                    # Network mapping interval 300s
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=300.0)
                        # If stop_event set, break out
                        break
                    except asyncio.TimeoutError:
                        continue

        recv_task = asyncio.create_task(_receive())
        hb_task = asyncio.create_task(_heartbeat())
        nm_task = asyncio.create_task(_network_mapper())

        done, pending = await asyncio.wait([recv_task, hb_task, nm_task], return_when=asyncio.FIRST_COMPLETED)

        # cancel any pending tasks
        for t in pending:
            t.cancel()
            try:
                await t
            except Exception:
                pass

        self.logger.debug("Interact finished (receive/heartbeat/network_mapper)")

    async def run(self, stop_event: Optional[asyncio.Event] = None):
        self.logger.info("CoreClient.run starting")
        # store ref so external stop() can set it
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