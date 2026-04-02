from unittest import case

from probe.init_app import action_map, parsers, probe_util, net_discovery, pcap, log_alert
import os
import json
from datetime import datetime, timezone
import xmltodict
from crontab import CronTab
from websockets.asyncio.client import ClientConnection

async def run_task(action: str, params: str = None, snmp_community: str = None):

    params_dict = json.loads(params) if params else None
    file_name = None
            
    if action == 'pcap_tux' or action == 'pcap_win':
        pcap.set_host(host=params_dict['tool_prms']['host'])
        pcap.set_credentials(user=params_dict['tool_prms']['usr'], password=params_dict['tool_prms']['pwd'])

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

        if 'target' not in params_dict['tool_prms'] and 'interface' not in params_dict:     
            params_dict['tool_prms']['target'] = probe_util.get_interface_subnet(interface=os.environ.get('DEFAULT_INTERFACE'))['network'] if os.environ.get('DEFAULT_INTERFACE') else probe_util.get_interface_subnet(interface=probe_util.get_ifaces()[0])['network']

            iface = os.environ.get('DEFAULT_INTERFACE') if os.environ.get('DEFAULT_INTERFACE') else probe_util.get_ifaces()[0]
            net_discovery.set_interface(iface)
        elif 'target' in params_dict['tool_prms'] and 'interface' in params_dict:
            net_discovery.set_interface(params_dict['interface'])

        net_discovery.set_command()

    handler = action_map.get(action)
    if handler and params_dict:
        code, output, error = await handler(**params_dict['tool_prms'])
    else:
        code, output, error = await handler()

    if file_name and os.path.exists(file_name):
        return code, output, error, file_name
    else:
        return code, output, error
        
async def parse_scan_results(action: str, file_name: str, probe_data_dict: dict, params_dict: dict, output: str):
    match action:
        case str() as s if s.startswith("scan_"):                   
            with open(file=f"{file_name}") as xml_file:
                nmap_dict = xmltodict.parse(xml_file.read())
                result = parsers.parse_nmap_json(nmap_dict)

        case str() as s if s.startswith("trcrt"):
            hops = parsers.parse_traceroute_output(output, action)
            result = {
                        "source": probe_data_dict.get('prb_id'),
                        "destination": params_dict['tool_prms']['target'],
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
            
    return result

def schedule_cronjob(job1: CronTab, core_act_data: dict):
    if 'minutes' in core_act_data and core_act_data['minutes']:
        minutes_range = str(core_act_data['minutes']).split(",")
        if isinstance(minutes_range, list):
            match len(minutes_range):
                case 3:
                    job1.minute.during(minutes_range[0], minutes_range[1]).every(minutes_range[2])
                case 2:
                    job1.minute.during(minutes_range[0], minutes_range[1])
                case 1:
                    job1.minute.every(minutes_range[0])

    if 'hours' in core_act_data and core_act_data['hours']:
        hours_range = str(core_act_data['hours']).split(",")
        if isinstance(hours_range, list):
            match len(hours_range):
                case 3:
                    job1.hour.during(hours_range[0], hours_range[1]).every(hours_range[2])
                case 2:
                    job1.hour.during(hours_range[0], hours_range[1])
                case 1:
                    job1.hour.every(hours_range[0])

    if 'dom' in core_act_data and core_act_data['dom']:
        dom_range = str(core_act_data['dom']).split(",")
        if isinstance(dom_range, list):
            match len(dom_range):
                case 3:
                    job1.dom.during(dom_range[0], dom_range[1]).every(dom_range[2])
                case 2:
                    job1.dom.during(dom_range[0], dom_range[1])
                case 1:
                    job1.dom.every(dom_range[0])

    if 'days' in core_act_data and core_act_data['days']:
        days_range = str(core_act_data['days']).split(",")
        if isinstance(days_range, list):
            job1.dow.on(days_range)

    if 'months' in core_act_data and core_act_data['months']:
        months_range = str(core_act_data['months']).split(",")
        if isinstance(months_range, list):
            match len(months_range):
                case 3:
                    job1.month.during(months_range[0], months_range[1]).every(months_range[2])
                case 2:
                    job1.month.during(months_range[0], months_range[1])
                case 1:
                    job1.month.every(months_range[0])
                                    
    return job1

async def send_smartbot_data(ws: ClientConnection, smartbot_data: dict, probe_data_dict: dict, tool_call_resp: dict):
    smartbot_call = {
        'act': 'smartbot',
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
    await ws.send(json.dumps(smartbot_call))