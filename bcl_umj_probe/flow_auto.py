import asyncio
import argparse
import os
import logging
from websockets.asyncio.client import connect
import json
from utils.RedisDB import RedisDB
from utils.FlowRunner import FlowRunner
from datetime import datetime, timezone
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.PacketCapture import PacketCapture
from utils.alerts_utils.SlackAlert import SlackAlert
from utils.alerts_utils.JiraSM import JiraSM
from utils.alerts_utils.EmailSenderHandler import EmailSenderHandler
from utils.alerts_utils.BotConnection import BotConnection
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.alerts_utils.LogAlert import LogAlert
from typing import Callable

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

net_discovery = NetworkDiscovery()
net_test = NetworkTest()
pcap = PacketCapture()
probe_util = ProbeInfo()
log_alert = LogAlert()
slack_alert = SlackAlert()
jira_alert = JiraSM()
email_alert = EmailSenderHandler()
bot_connection = BotConnection()

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
    "pcap_win": pcap.pcap_remote_windows,
    "slack": slack_alert.send_alert_message,
    "jira": jira_alert.send_alert,
    "bot": bot_connection.mcp_exec,
    "email": email_alert.send_transactional_email,
}

net_discovery.set_interface(probe_util.get_ifaces()[0])

prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))

async def run_flow(flow: str, ws_url: str, probe_data: str, flow_name: str):
    flow_runner = FlowRunner()
    tool_output, alerts, agents = await flow_runner.run(flow_str=flow)
    probe_data_dict = json.loads(probe_data)

    tool_outputs = "\n\n".join([f"Probe: {output['prb']} \n\n{output['tool']} Output:\n{output['result']}" for output in tool_output])

    async with connect(uri=ws_url) as websocket:
        if 'agent' in agents and agents['agent'] == 'smartbot':
        
            smartbot_call = {
                 'act': 'smartbot_flow',
                 'url': f"{probe_data_dict.get('url')}/llm/mcp",
                 'tool_output': tool_output,
                 'prompt': agents['prompt'],
                 'prb_api_key': probe_data_dict.get('prb_api_key'),
                 'prb_id': probe_data_dict.get('prb_id'),
                 'prb_name': probe_data_dict.get('name'),
                 'site': probe_data_dict.get('site'),
                 'alerts': alerts  ,
                 'task_type': 'flow',
                 'flow_name': flow_name,
            }

            await websocket.send(json.dumps(smartbot_call))

        if alerts:
            for alert in alerts.values():
                match alert['tool']:
                    case 'slack':
                     slack_alert.set_slack_connection_info(slack_bot_token=os.environ.get('slack-token'), slack_channel_id=os.environ.get('slack-channel'))
                    case 'jira':
                     jira_alert.set_jira_connection_info(cloud_id=os.environ.get('jira-cloud-id'), auth_email=os.environ.get('jira-auth-email'), auth_token=os.environ.get('jira-auth-token'))
                    case 'email' | _:
                        email_alert.set_brevo_api_key(os.environ.get('brevo-api-key'))
                        tool_outputs = "\n\n".join([f"Probe: {output['prb']} \n\n{output['tool']} Output:\n{output['result']}" for output in tool_output])
                        html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                            <p>Flow Alert</p>
                            <p>Probe: {probe_data_dict.get('name')}</p>
                            <p>Site: {probe_data_dict.get('site')}</p>
                            <p>Result: {tool_outputs}</p>
                            </div>"""
                        send_result = asyncio.to_thread(
                        email_alert.send_transactional_email, 
                        sender={'name': f'Probe: {probe_data_dict.get("name")}', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                        to=[{"name": os.environ.get('BREVO_RECIPIENT_NAME'), "email": os.environ.get('BREVO_RECIPIENT_EMAIL')}],
                        subject=f"Flow Alert: {flow_name} executed on probe {probe_data_dict.get('name')}",
                        html_content=html_snippet
                        )
                        logger.info(type(send_result))

        flow_result = {
                'site': probe_data_dict.get('site'),
                'task_output': tool_outputs,
                'prb_id': probe_data_dict.get('prb_id'),
                'prb_name': probe_data_dict.get('name'),
                'assigned_user': probe_data_dict.get('assigned_user'),
                'task_type': 'flow',
                'timestamp': datetime.now(tz=timezone.utc).isoformat(),
                'act': "prb_task_rslt",
                'name': flow_name,
            }
            
        await websocket.send(json.dumps(flow_result))    
                
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate network monitoring tasks.")
    parser.add_argument(
        '-f', '--flow', 
        type=str, 
        help="Flow to execute"
    )
    parser.add_argument(
        '-n', '--flow_name', 
        type=str, 
        help="Name of the flow to execute"
    )
    parser.add_argument(
        '-w', '--ws_url', 
        type=str, 
        help="WebSocket URL for reporting results"
    )
    parser.add_argument(
        '-pdta', '--probe_data', 
        type=dict, 
        help="Probe data for reporting results"
    )
    args = parser.parse_args()

    asyncio.run(run_flow(flow=args.flow, ws_url=args.ws_url, probe_data=args.probe_data, flow_name=args.flow_name))