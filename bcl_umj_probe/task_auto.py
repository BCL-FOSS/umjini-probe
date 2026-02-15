from datetime import datetime
import asyncio
import argparse
import os
import logging
from datetime import datetime, timezone
from websockets.asyncio.client import connect
import json
from utils.RedisDB import RedisDB
from init_app import action_map, pcap, log_alert, parsers, net_discovery, net_test, slack_alert, jira_alert, email_alert, bot_connection, probe_util
import xmltodict
from net_util_api import prb_id

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))

async def automate_task(action: str, params: str, ws_url: str, probe_data: str, task_name: str):
    async with connect(uri=ws_url) as websocket:
        params_dict = json.loads(params)
        probe_data_dict = json.loads(probe_data)

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
                        "source": prb_id,
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
            task_result = {
                'site': probe_data_dict['site'],
                'task_output': result,
                'prb_id': probe_data_dict['prb_id'],
                'prb_name': probe_data_dict['name'],
                'task_type': action,
                'timestamp': datetime.now(tz=timezone.utc).isoformat(),
                'act': "prb_task_rslt",
                'name': task_name,
                'llm': params_dict['llm']
                                    }
            
            await websocket.send(json.dumps(task_result))
        else:
            logger.error(f"Action '{action}' not found in action map.")
            return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate network monitoring tasks.")
    parser.add_argument(
        '-a', '--action', 
        type=str, 
        help="Network task to perform"
    )
    parser.add_argument(
        '-p', '--params', 
        type=dict, 
        help="params_dict for the network task"
    )
    parser.add_argument(
        '-w', '--ws_url', 
        type=str, 
        help="WebSocket URL for reporting results"
    )
    parser.add_argument(
        '-pid', '--prb_id', 
        type=str, 
        help="Probe " \
        "ID for reporting results"
    )
    parser.add_argument(
        '-s', '--site', 
        type=str, 
        help="Site for reporting results"
    )
    parser.add_argument(
        '-llm', '--llmanalysis', 
        action='store_true', 
        help="Enable debug logging"
    )
    parser.add_argument(
        '-pdta', '--probe_data', 
        type=dict, 
        help="Probe data for reporting results"
    )
    parser.add_argument(
        '-n', '--name', 
        type=str, 
        help="Name for reporting results"
    )
    args = parser.parse_args()

    asyncio.run(automate_task(action=args.action, params=args.params, ws_url=args.ws_url, prb_id=args.prb_id, site=args.site, llm=args.llmanalysis, probe_data=args.probe_data, name=args.name))