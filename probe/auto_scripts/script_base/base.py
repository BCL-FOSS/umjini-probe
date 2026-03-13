from probe.init_app import action_map, parsers, probe_util, net_discovery, pcap
import os
import json
from datetime import datetime, timezone
import xmltodict

async def run_task(action: str, params: str, snmp_community: str = None):
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

        if 'target' not in params_dict and (action == 'scan_full' or action == 'scan_snmp'):     
            params_dict['target'] = probe_util.get_interface_subnet(interface=os.environ.get('DEFAULT_INTERFACE'))['network'] if os.environ.get('DEFAULT_INTERFACE') else probe_util.get_interface_subnet(interface=probe_util.get_ifaces()[0])['network']
        elif 'target' in params_dict and 'interface' in params_dict and (action == 'scan_full' or action == 'scan_snmp'):
            net_discovery.set_interface(params_dict['interface'])

        net_discovery.set_command()

    handler = action_map.get(action)
    if handler and params_dict:
        code, output, error = await handler(**params_dict)

    if code == 0:
        return code, output, error, file_name
        
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
            
    return result