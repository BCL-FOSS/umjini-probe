from datetime import datetime
import asyncio
import argparse
import os
from datetime import datetime, timezone
from websockets.asyncio.client import connect
import json
import xmltodict
from probe.init_app import action_map, log_alert, parsers, probe_util, net_discovery, pcap


async def automate_task(action: str, params: str, ws_url: str, probe_data: str, llm_data: str = None, snmp_community: str = None):
    async with connect(uri=ws_url) as websocket:
        params_dict = json.loads(params)
        probe_data_dict = json.loads(probe_data)
        smartbot_data = json.loads(llm_data) if llm_data is not None else None

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

    asyncio.run(automate_task(action=args.action, params=args.params, ws_url=args.ws_url, prb_id=args.prb_id, probe_data=args.probe_data, llm_data=args.llm_data, snmp_community=args.snmp_community))