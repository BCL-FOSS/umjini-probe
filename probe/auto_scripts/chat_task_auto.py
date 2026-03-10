from datetime import datetime
import asyncio
import argparse
import os
from datetime import datetime, timezone
from websockets.asyncio.client import connect
import json
import xmltodict
from probe.init_app import action_map, log_alert, parsers, probe_util, net_discovery, pcap

async def automate_task(ws_url: str, probe_data: str, llm: str = None, llm_data: str = None, snmp_community: str = None, tool_calls: list[dict] = None):
    async with connect(uri=ws_url) as websocket:
        probe_data_dict = json.loads(probe_data)
        smartbot_data = json.loads(llm_data) if llm_data is not None else None
        tool_call_resp = {}

        for tool_call in tool_calls:
            action = tool_call.get('name')
            params = tool_call.get('arguments')
            params_dict = json.loads(params)
            
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
                net_discovery.set_output_file(file_name)

                if action == 'scan_snmp' and snmp_community is not None:
                    net_discovery.set_community_string(snmp_community)
                
                if net_discovery.get_interface() == os.environ.get('DEFAULT_INTERFACE'):
                    params_dict['subnet'] = probe_util.get_interface_subnet(interface=os.environ.get('DEFAULT_INTERFACE'))['network']
                else:
                    params_dict['subnet'] = probe_util.get_interface_subnet(interface=probe_util.get_ifaces()[0])['network']

                net_discovery.set_command()

            handler = action_map.get(action)
            if handler and params_dict:
                code, output, error = await handler(**params_dict)

            if code == 0:
                if action.startswith("scan_") and os.path.exists(file_name):
                    tool_call_resp[action] = {
                        "code": code,
                        "output": output,
                        "error": error,
                        "file": file_name
                    }
                else:
                    tool_call_resp[action] = {
                        "code": code,
                        "output": output,
                        "error": error
                    } 

            match action:
                case str() as s if s.startswith("scan_"):               
                    with open(file=f"{tool_call_resp['file']}") as xml_file:
                        nmap_dict = xmltodict.parse(xml_file.read())
                        tool_call_resp['parsed'] = parsers.parse_nmap_json(nmap_dict)

                case str() as s if s.startswith("trcrt"):
                    hops = parsers.parse_traceroute_output(output, action)
        
                    tool_call_resp['parsed'] = {
                        "source": probe_data_dict.get('prb_id'),
                        "destination": params_dict['target'],
                        "trace_type": action,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "hops": hops
                    }

                case str() as s if s.startswith("test_"):
                    if action == 'test_srvr':
                        tool_call_resp['parsed'] = {
                            "mode": "server",
                            "server_ip": "0.0.0.0",
                            "server_port": "7969",
                            "status": "listening",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }

                    if action == 'test_clnt':
                        iperf_data = json.loads(output)
                        tool_call_resp['parsed'] = parsers.parse_iperf_output(iperf_data)

                case str() as s if s.startswith("pcap_"):
                    packets = parsers.parse_pcap_summary(output)
        
                    tool_call_resp['parsed'] = {
                        "capture_mode": action,
                        "interface": params_dict['interface'],
                        "packet_count": len(packets),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "packets": packets
                    }  
            
        log_message=f"{json.dumps(tool_call_resp)}"

        timestamp = datetime.now(tz=timezone.utc).isoformat()

        await log_alert.write_log(log_name=f"{action}_result_{timestamp}", message=log_message)

        
        smartbot_call = {
                 'act': 'smartbot_chat_auto',
                 'url': f"{probe_data_dict.get('url')}/llm/mcp",
                 'tool_output': json.dumps(tool_call_resp),
                 'task_type': "chat_task",
                 'prompt': smartbot_data.get('prompt'),
                 'prb_api_key': probe_data_dict.get('prb_api_key'),
                 'prb_id': probe_data_dict.get('prb_id'),
                 'prb_name': probe_data_dict.get('name'),
                 'site': probe_data_dict.get('site'),
                 'alerts': {'tool': smartbot_data.get('alerts')}
            }
                
        await websocket.send(json.dumps(smartbot_call))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate network monitoring tasks.")
    parser.add_argument(
        '-t', '--tool_calls', 
        type=str, 
        help="Tools to execute"
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
        '-snmp', '--snmp_community', 
        type=str, 
        help="SNMP community string for nmap SNMP scans"
    )
    args = parser.parse_args()

    asyncio.run(automate_task(ws_url=args.ws_url, prb_id=args.prb_id, probe_data=args.probe_data, llm=args.smartbot, llm_data=args.llm_data, snmp_community=args.snmp_community, tool_calls=json.loads(args.tool_calls)))