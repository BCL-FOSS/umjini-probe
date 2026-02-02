import asyncio
import websockets
import os
from websockets import ClientConnection, ConnectionClosed
from typing import Callable
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.PacketCapture import PacketCapture
import os
import logging
import inspect
from utils.RedisDB import RedisDB
import json
from websockets import ConnectionClosed
from typing import Optional
from websockets.asyncio.client import connect
from crontab import CronTab
import asyncio
import ast

net_discovery = NetworkDiscovery()
net_test = NetworkTest()
pcap = PacketCapture()
probe_util = ProbeInfo()

net_discovery.set_interface(probe_util.get_ifaces()[0])

action_map: dict[str, Callable[[dict], object]] = {
    "trcrt_dns": net_test.dnstraceroute,
    "trcrt": net_test.traceroute,
    "test_srvr": net_test.iperf_server,
    "test_clnt": net_test.iperf_client,
    "scan_arp": net_discovery.arp_scan,
    "scan_custom": net_discovery.custom_scan,
    "scan_dev_id": net_discovery.device_identification_scan,
    "scan_dev_fngr": net_discovery.device_fingerprint_scan,
    "scan_full": net_discovery.full_network_scan,
    "scan_snmp": net_discovery.snmp_scans,
    "scan_port": net_discovery.port_scan,
    "pcap_lcl": pcap.pcap_local,
    "pcap_tux": pcap.pcap_remote_linux,
    "pcap_win": pcap.pcap_remote_windows
}

class CoreClient:
    def __init__(self, umj_ws_url: str):
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.logger = logging.getLogger(__name__)
        self.umj_ws = umj_ws_url
        self.prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
        
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
        probe_data = await self.prb_db.get_all_data(match='prb-*')
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
                    prb_task_action = core_act_data['task']
                    params = core_act_data['prms']

                    if core_act_data['automate'] == 'y':
                        ws_url = f"wss://{probe_obj.get('umj_url')}/heartbeat/{probe_obj.get('prb_id')}"
                        cron=CronTab()
                        cwd = os.getcwd()
                        script_path = os.path.join(cwd, 'task_auto.py')
                        job1=cron.new(command=f"python3 {script_path} -a {prb_task_action} -p '{params}' -w {ws_url} -pid {probe_obj.get('prb_id')} -s {probe_obj.get('site')} -llm {core_act_data['llm_analysis']}", comment=f"auto_task_{probe_obj.get('prb_id')}_{prb_task_action}")

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
                                'act_rslt': f"Cron job added for task {prb_task_action}.",
                                'prb_id': probe_obj.get('prb_id'),
                                'act_rslt_type': f'cron_job_{prb_task_action}',
                                'act': "prb_task_rslt"
                            }))
                        else:
                            self.logger.error("Invalid cron job, not writing to crontab.")
                    else:
                        match prb_task_action:
                            case 'pcap_tux' | 'pcap_win':
                                pcap.set_host(host=core_act_data['host'])
                                pcap.set_credentials(user=core_act_data['usr'], password=core_act_data['pwd'])

                        handler = action_map.get(prb_task_action)
                        if handler and params:
                            if inspect.iscoroutinefunction(handler):
                                result = await handler(**params)
                            else:
                                result = handler(**params)
                                
                        if handler:
                            if inspect.iscoroutinefunction(handler):
                                result = await handler()
                            else:
                                result = handler()

                        task_result = {
                                'site': probe_obj.get('site'),
                                'task_output': result,
                                'prb_id': probe_obj.get('prb_id'),
                                'name': probe_obj.get('name'),
                                'task_type': f'{prb_task_action}',
                                'act': "prb_task_rslt",
                                'llm': core_act_data['llm_analysis']
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

        # run both tasks and wait until one completes
        recv_task = asyncio.create_task(_receive())
        hb_task = asyncio.create_task(_heartbeat())

        done, pending = await asyncio.wait([recv_task, hb_task], return_when=asyncio.FIRST_COMPLETED)

        # cancel any pending tasks
        for t in pending:
            t.cancel()
            try:
                await t
            except Exception:
                pass

        self.logger.debug("Interact finished (receive/heartbeat)")

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