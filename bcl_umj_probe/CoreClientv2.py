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
import httpx
import json
from websockets import ConnectionClosed
from websockets.exceptions import InvalidHandshake
from typing import Optional
import random

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
    "arp": net_discovery.arp_scan,
    "dev_classify": net_discovery.custom_scan,
    "dev_id": net_discovery.device_identification_scan,
    "dev_fngr": net_discovery.device_fingerprint_scan,
    "net_scan": net_discovery.full_network_scan,
    "snmp_scans": net_discovery.snmp_scans,
    "service_id": net_discovery.port_scan,
    "pcap_lcl": pcap.pcap_local,
    "pcap_tux": pcap.pcap_remote_linux,
    "pcap_win": pcap.pcap_remote_windows
}

class CoreClient:
    def __init__(self, umj_url: str, umj_token: str, umj_ws_url: str):
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.logger = logging.getLogger(__name__)
        self.umj_url = umj_url
        self.umj_token = umj_token
        self.umj_ws = umj_ws_url
        self.prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))

    async def make_request(self, url: str, umj_key: str = None):
        async with httpx.AsyncClient() as client:
            headers = {"X-UMJ-WFLW-API-KEY": umj_key}
            return await client.get(url=url, headers=headers)
        
    def stop(self):
            """
            Request the client to stop. If run() was started with a stop_event,
            this will set that event. Also sets an internal stop flag so run()
            knows to exit if called without an external event.
            """
            # If external stop_event exists, set it
            if getattr(self, "_stop_event", None) is not None:
                try:
                    self._stop_event.set()
                except Exception:
                    pass
            # Set internal flag
            self._internal_stop = True

    async def connect_with_backoff(self, ws_url: str, access_token: str, init_url: str, stop_event: Optional[asyncio.Event] = None):
        """
        Persistent connection loop with exponential backoff + jitter that respects stop_event.
        - ws_url: websocket URL
        - access_token: cookie token to send
        - init_url: URL to refresh token from (server init endpoint)
        - stop_event: asyncio.Event used to request shutdown externally
        """
        backoff = 1.0
        max_backoff = 60.0
        retry_counter = 0

        await self.prb_db.connect_db()
        probe_data = await self.prb_db.get_all_data(match='prb-*')
        probe_data_dict = next(iter(probe_data.values()))

        if stop_event is None:
            stop_event = asyncio.Event()
        # store reference for stop() to set if called
        self._stop_event = stop_event
        self._internal_stop = False

        logger = getattr(self, "logger", logging.getLogger(__name__))
        logger.info("CoreClient: entering connect_with_backoff loop")

        while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
            headers = {
                # websockets client supports extra_headers as list/sequence or mapping depending on version
                # We'll supply a list of tuples for compatibility
                "Cookie": f"access_token={access_token}"
            }
            # websockets.connect expects extra_headers param name (not additional_headers) for latest versions
            extra_headers = [("Cookie", f"access_token={access_token}")]

            try:
                async with websockets.connect(
                    uri=ws_url,
                    extra_headers=extra_headers,
                    ping_interval=20,
                    ping_timeout=10,
                ) as ws:
                    logger.info("Connected to %s", ws_url)
                    backoff = 1.0
                    retry_counter = 0

                    # Run interaction until it returns (connection closed or stop requested).
                    try:
                        await self.interact(ws, probe_obj=probe_data_dict, stop_event=stop_event)
                    except asyncio.CancelledError:
                        logger.info("Interaction cancelled")
                        raise
                    except ConnectionClosed as cc:
                        logger.warning(f"Websocket closed: {cc}")
                    except Exception:
                        logger.exception("Error during interaction")

                    # If stop requested, break the outer loop
                    if stop_event.is_set() or getattr(self, "_internal_stop", False):
                        logger.info("Stop requested, exiting connect loop after clean disconnect")
                        break

                    # Otherwise the socket closed unexpectedly; attempt reconnect with a short pause
                    logger.info(f"Socket closed, will attempt reconnect (backoff={backoff})")
                    # small delay to avoid tight reconnect loop
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=0.5)
                        break
                    except asyncio.TimeoutError:
                        pass

            except (InvalidHandshake, OSError) as e:
                logger.error(f"WebSocket connection error (handshake/OSError): {e}")
            except asyncio.CancelledError:
                logger.info("connect_with_backoff cancelled")
                break
            except Exception as e:
                logger.exception(f"Unexpected error connecting websocket: {e}")

            # Attempt to refresh token via init_url before reconnecting (if possible)
            try:
                umj_api_key = probe_data_dict.get('umj_api_key')
                if init_url and umj_api_key:
                    umj_response = await self.make_request(url=init_url, umj_key=umj_api_key)
                    if umj_response.status_code != 200:
                        logger.error(f"Failed to refresh access_token (init returned {umj_response.status_code}). Stopping reconnect attempts.")
                        break
                    new_token = umj_response.cookies.get("access_token")
                    if not new_token:
                        logger.error("No access_token returned when refreshing token. Stopping reconnect attempts.")
                        break
                    access_token = new_token
                else:
                    logger.debug("No init_url or api_key provided; skipping token refresh")
            except Exception as e:
                logger.warning(f"Error refreshing access token: {e}")

            # Exponential backoff with jitter (but watch stop_event)
            jitter = random.uniform(0, min(3.0, backoff))
            sleep_for = min(backoff + jitter, max_backoff)
            logger.info(f"Waiting {sleep_for:.2f}s before reconnect (backoff={backoff:.1f}, jitter={jitter:.2f})")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=sleep_for)
                # stop_event set -> exit
                break
            except asyncio.TimeoutError:
                # timed out, continue reconnect attempts
                pass

            backoff = min(backoff * 2, max_backoff)
            retry_counter += 1

        logger.info("CoreClient: exiting connect_with_backoff")

    async def interact(self, ws: websockets.WebSocketClientProtocol, probe_obj: dict, stop_event: Optional[asyncio.Event] = None):
        """
        Run receive and heartbeat tasks concurrently until one finishes or stop_event is set.
        Ensures tasks are cancelled and cleaned up properly.
        """
        if stop_event is None:
            stop_event = asyncio.Event()

        logger = getattr(self, "logger", logging.getLogger(__name__))

        async def _receive():
            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                try:
                    raw_message = await ws.recv()
                except ConnectionClosed as cc:
                    logger.warning(f"Receive: connection closed: {cc}")
                    break
                except asyncio.CancelledError:
                    logger.debug("Receive task cancelled")
                    break
                except Exception as e:
                    logger.exception(f"Receive: unexpected error: {e}")
                    break

                # Safely parse JSON if possible
                try:
                    core_act_data = json.loads(raw_message)
                except Exception:
                    logger.debug(f"Received non-JSON message: {raw_message}")
                    continue

                if core_act_data.get('remote_act') == 'prb_analysis':
                    probe_id = core_act_data.get('prb_id')
                    if probe_id and probe_id == probe_obj.get('prb_id'):
                        action = core_act_data.get("act")
                        params = core_act_data.get("prms", {})

                        # Some actions require setting credentials/host
                        match action:
                            case 'pcap_tux' | 'pcap_win':
                                pcap.set_host(host=core_act_data.get('host'))
                                pcap.set_credentials(user=core_act_data.get('usr'), password=core_act_data.get('pwd'))

                        handler = action_map.get(action)
                        result = None
                        if handler:
                            try:
                                if inspect.iscoroutinefunction(handler):
                                    result = await handler(**(params or {}))
                                else:
                                    # run sync handler in default loop safely if it may block?
                                    result = handler(**(params or {}))
                            except Exception:
                                logger.exception(f"Handler for action {action} raised")

                        # Build and serialize result before sending
                        umj_result_data = {
                            'site': probe_obj.get('site'),
                            'act_rslt': result,
                            'prb_id': probe_obj.get('prb_id'),
                            'act_rslt_type': f'{action}',
                            'act': "prb_act_rslt"
                        }
                        try:
                            await ws.send(json.dumps(umj_result_data))
                        except Exception:
                            logger.exception("Failed to send result over websocket")

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
                    logger.warning("Heartbeat: connection closed")
                    break
                except asyncio.CancelledError:
                    break
                except Exception:
                    logger.exception("Heartbeat: failed to send ping")
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

        logger.debug("Interact finished (receive/heartbeat)")

    async def run(self, stop_event: Optional[asyncio.Event] = None):
        """
        Async entrypoint to start the persistent connection logic.
        Accepts an optional asyncio.Event 'stop_event' which can be set externally to request a clean shutdown.
        Example:
            stop_event = asyncio.Event()
            asyncio.create_task(core_client.run(stop_event))
        """
        logger = getattr(self, "logger", logging.getLogger(__name__))
        logger.info("CoreClient.run starting")
        # store ref so external stop() can set it
        if stop_event is None:
            stop_event = asyncio.Event()
        self._stop_event = stop_event
        self._internal_stop = False

        try:
            await self.connect_with_backoff(ws_url=self.umj_ws, access_token=self.umj_token, init_url=self.umj_url, stop_event=stop_event)
        except asyncio.CancelledError:
            logger.info("CoreClient.run cancelled")
            raise
        except Exception:
            logger.exception("Unhandled exception in CoreClient.run")
        finally:
            logger.info("CoreClient.run finished")