from datetime import datetime
import asyncio
import argparse
import os
import logging
from datetime import datetime, timezone
from websockets.asyncio.client import connect
import json
from utils.RedisDB import RedisDB
import xmltodict
from utils.Parsers import Parsers
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
parsers = Parsers()

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

async def automate_task(action: str, params: str, ws_url: str, probe_data: str, task_name: str, llm: str = None, llm_data: str = None, alert_type: str = None):
    async with connect(uri=ws_url) as websocket:
        params_dict = json.loads(params)
        probe_data_dict = json.loads(probe_data)
        smartbot_data = json.loads(llm_data) if llm_data is not None else None
        alert_data = json.loads(alert_type) if alert_type is not None else None

        if action == 'pcap_tux' or action == 'pcap_win':
            pcap.set_host(host=params_dict['host'])
            pcap.set_credentials(user=params_dict['usr'], password=params_dict['pwd'])

        if action.startswith("scan_"):
            cur_dir = os.getcwd()
            scan_dir = os.path.join(cur_dir, "nmap_scans")
            if not os.path.exists(scan_dir):
                                    os.makedirs(scan_dir)

            timestamp = datetime.now(tz=timezone.utc).isoformat()
            exec_name = f"{action}_result_{timestamp}"
            file=os.path.join(scan_dir, exec_name)
            file_name = f"{file}.xml"
            params_dict['export_file_name'] = file_name

            if 'interface' not in params_dict or not params_dict['interface']:
                net_discovery.set_interface(probe_util.get_ifaces()[0])
                params_dict['subnet'] = probe_util.get_interface_subnet(interface=probe_util.get_ifaces()[0])['network']

            if 'subnet' not in params_dict or not params_dict['subnet'] and params_dict['interface']:
                net_discovery.set_interface(params_dict['interface'])
                params_dict['subnet'] = probe_util.get_interface_subnet(interface=params_dict['interface'])['network']

        handler = action_map.get(action)
        if handler and params_dict:
            code, output, error = await handler(**params_dict)

        if code != 0:
            log_message=f""
            log_message+=f"{code}\n\n"
            log_message+=f"{output}\n\n"
            log_message+=f"{error}"

            timestamp = datetime.now(tz=timezone.utc).isoformat()

            await log_alert.write_log(log_name=f"{action}_result_{timestamp}", message=log_message)

            match action:
                case str() as s if s.startswith("scan_"):
                                        
                    with open(file=f"{file_name}") as xml_file:
                        nmap_dict = xmltodict.parse(xml_file.read())

                                        #nmap_json = json.dumps(nmap_dict)
                        result = parsers.parse_nmap_json(nmap_dict)

                case str() as s if s.startswith("trcrt"):
                    hops = parsers.parse_traceroute_output(output, action)
        
                    result = {
                        "source": probe_data_dict.get('prb_id'),
                        "destination": params_dict['target'],
                        "trace_type": action,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "hops": hops
                    }

                case str() as s if s.startswith("test_"):
                    if action == 'test_srvr':
                        result = {
                            "mode": "server",
                            "server_ip": "0.0.0.0",
                            "server_port": "7969",
                            "status": "listening",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }

                    if action == 'test_clnt':
                        iperf_data = json.loads(output)
                        result = parsers.parse_iperf_output(iperf_data)

                case str() as s if s.startswith("pcap_"):
                    packets = parsers.parse_pcap_summary(output)
        
                    result = {
                        "capture_mode": action,
                        "interface": params_dict['interface'],
                        "packet_count": len(packets),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "packets": packets
                    }

        if llm == 'smartbot' and smartbot_data is not None:
            smartbot_call = {
                 'act': 'smartbot_task',
                 'url': f"{probe_data_dict.get('url')}/llm/mcp",
                 'tool_output': result,
                 'task_type': action,
                 'prompt': smartbot_data.get('prompt'),
                 'prb_api_key': probe_data_dict.get('prb_api_key'),
                 'prb_id': probe_data_dict.get('prb_id'),
                 'prb_name': probe_data_dict.get('name'),
                 'site': probe_data_dict.get('site'),
                 'alerts': {'tool': smartbot_data.get('alerts')}
            }
                
            await websocket.send(json.dumps(smartbot_call))

        alert_data = json.loads(alert_type)
        match alert_data.get('type'):
            case 'slack':
                slack_alert.set_slack_connection_info(slack_bot_token=os.environ.get('slack-token'), slack_channel_id=os.environ.get('slack-channel'))
            case 'jira':
                jira_alert.set_jira_connection_info(cloud_id=os.environ.get('jira-cloud-id'), auth_email=os.environ.get('jira-auth-email'), auth_token=os.environ.get('jira-auth-token'))
            case 'email' | _:
                email_alert.set_brevo_api_key(os.environ.get('brevo-api-key'))
                html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                        <p>Task Alert</p>
                        <p>Probe: {probe_data_dict.get('name')}</p>
                        <p>Site: {probe_data_dict.get('site')}</p>
                        <p>Action: {action}</p>
                        <p>Result: {output}</p>
                        </div>"""
                send_result = asyncio.to_thread(
                        email_alert.send_transactional_email, 
                        sender={'name': f'Probe: {probe_data_dict.get("name")}', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                        to=[{"name": os.environ.get('BREVO_RECIPIENT_NAME'), "email": os.environ.get('BREVO_RECIPIENT_EMAIL')}],
                        subject=f"Task Alert: {action} executed on probe {probe_data_dict.get('name')}",
                        html_content=html_snippet
                        )
                logger.info(type(send_result))

        task_result = {
                'site': probe_data_dict['site'],
                'task_output': output,
                'prb_id': probe_data_dict['prb_id'],
                'prb_name': probe_data_dict['name'],
                'assigned_user': probe_data_dict['assigned_user'],
                'task_type': action,
                'timestamp': datetime.now(tz=timezone.utc).isoformat(),
                'act': "prb_task_rslt",
                'name': task_name,
                                    }
            
        await websocket.send(json.dumps(task_result))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate network monitoring tasks.")
    parser.add_argument(
        '-a', '--action', 
        type=str, 
        help="Network task to perform"
    )
    parser.add_argument(
        '-p', '--params', 
        type=str, 
        help="params_dict for the network task"
    )
    parser.add_argument(
        '-w', '--ws_url', 
        type=str, 
        help="WebSocket URL for reporting results"
    )
    parser.add_argument(
        '-pdta', '--probe_data', 
        type=str, 
        help="Probe data for reporting results"
    )
    parser.add_argument(
        '-n', '--name', 
        type=str, 
        help="Name for reporting results"
    )
    parser.add_argument(
        '-llm', '--smartbot', 
        type=str, 
        help="Whether to send results to smartbot for further analysis and alerting"
    )
    parser.add_argument(
        '-llmdta', '--llm_data', 
        type=str, 
        help="Data for smartbot to determine alerts and analysis (e.g., prompt, alert preferences)"
    )
    parser.add_argument(
        '-alert', '--alert_type', 
        type=str, 
        help="Whether to send alerts and which type of alert to send (e.g., slack, jira, email)"
    )
    args = parser.parse_args()

    asyncio.run(automate_task(action=args.action, params=args.params, ws_url=args.ws_url, prb_id=args.prb_id, probe_data=args.probe_data, task_name=args.name, llm=args.smartbot, alert_type=args.alert_type, llm_data=args.llm_data))