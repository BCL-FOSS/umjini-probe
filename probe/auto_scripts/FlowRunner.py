import datetime
import logging
import ast
import os
from utils.RedisDB import RedisDB
from datetime import datetime, timezone
from probe.init_app import action_map, log_alert, probe_util, net_discovery, pcap

class FlowRunner:
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.logger = logging.getLogger(__name__)
        self.prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))

    async def get_probe_data(self):
        await self.prb_db.connect_db()
        probe_data = await self.prb_db.get_all_data(match='prb:*')
        probe_data_dict = next(iter(probe_data.values()))
        return probe_data_dict

    async def run(self, flow_str: str):
        probe_data_dict = await self.get_probe_data()
        self.logger.info(f"Probe Data From FlowRunner: {probe_data_dict}")

        flow_dict = ast.literal_eval(flow_str)

        # Parsed flow data
        workflow = flow_dict
        self.logger.info(workflow)
        workflow_data = workflow['drawflow']['Home']['data']
        self.logger.info(workflow_data)

        node_output_mapping = {}
        alerts = {}
        agents = {}
        remote_tools_to_execute = {}
        local_tools_to_execute = {}
        remote_tool_params = {}
                
        for node_id, node in workflow_data.items():
            node_data = node.get('data')
            match node_data['name']:
                case str() as s if s.startswith('prb:'):
                    if node_data['prb-trcrttype']:
                        remote_tool_params['target'] = node_data['prb-trcrttarget']

                        if node_data['prb-trcrtoptions']:
                            remote_tool_params['options'] = node_data['prb-trcrtoptions']
                        if node_data['prb-trcrtpktlen']:
                            remote_tool_params['packetlen'] = node_data['prb-trcrtpktlen']
                        if node_data['prb-trcrtdnsserver'] and node_data['prb-trcrttype'] == 'trcrt_dns':
                            remote_tool_params['server'] = node_data['prb-trcrtdnsserver']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-trcrttype'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                    if node_data['prb-perftype']:

                        if node_data['prb-perfoptions']:
                            remote_tool_params['options'] = node_data['prb-perfoptions']
                        if node_data['prb-perfserver'] and node_data['prb-perftype'] == 'spdtst_clnt':
                            remote_tool_params['server'] = node_data['prb-perfserver']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-perftype'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                    if node_data['prb-scanstype']:
                        if node_data['prb-scantarget']:
                            remote_tool_params['target'] = node_data['prb-scantarget']

                        if node_data['prb-scandevidnoise'] == 'n' and node_data['prb-scanstype'] == 'scan_dev_id':
                            remote_tool_params['limit'] = False

                        if node_data['prb-scanfplimit'] == 'y' and node_data['prb-scanstype'] == 'scan_dev_fngr':
                            remote_tool_params['noise'] = True

                        if node_data['prb-scansnamptype'] and node_data['prb-scanstype'] == 'scan_snmp':
                            remote_tool_params['type'] = node_data['prb-scansnamptype']

                        if node_data['prb-snmpscanscripts'] and node_data['prb-scanstype'] == 'scan_snmp':
                            remote_tool_params['scripts'] = node_data['prb-snmpscanscripts']

                        if node_data['prb-snmpcommunity'] and node_data['prb-scanstype'] == 'scan_snmp':
                            remote_tool_params['community'] = node_data['prb-snmpcommunity']

                        if node_data['prb-scanoptions']:
                            remote_tool_params['options'] = node_data['prb-scanoptions']

                        if node_data['prb-scanports'] and node_data['prb-scanstype'] == 'scan_port':
                            remote_tool_params['ports'] = node_data['prb-scanports']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-scanstype'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                    if node_data['prb-pcapmode']:
                        if node_data['prb-pcapmode'] != 'pcap_lcl' and node_data['prb-pcaptrmuser'] and node_data['prb-pcaptrmpass'] and node_data['prb-pcaptrmhost']:
                            remote_tool_params['username'] = node_data['prb-pcaptrmuser']
                            remote_tool_params['password'] = node_data['prb-pcaptrmpass']
                            remote_tool_params['host'] = node_data['prb-pcaptrmhost']

                        if node_data['prb-pcapmode'] == 'pcap_lcl' and node_data['prb-pcapcount']:
                            remote_tool_params['cap_count'] = node_data['prb-pcapcount']

                        if node_data['prb-pcapduration'] and node_data['prb-pcapmode'] == 'pcap_win':
                            remote_tool_params['duration'] = node_data['prb-pcapduration']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-pcapmode'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                case 'scan_arp':
                    params = {}
                    if node_data['arp-target']:
                        params['subnet'] = node_data['arp-target']

                    if node_data['arp-interface']:
                        net_discovery.set_interface(node_data['arp-interface'])
                        params['subnet'] = probe_util.get_interface_subnet(node_data['arp-interface'])['network']

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}
                    params = {}

                case 'scan_custom':
                    params = {}
                    if node_data['custom-target']:
                        params['target'] = node_data['custom-target']

                    if node_data['custom-options']:
                        params['options'] = node_data['custom-options']

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'scan_dev_id':
                    if node_data['devid-target']:
                        params = {'target': node_data['devid-target']}

                    if node_data['devid-noise'] == 'n':
                        params['noise'] = True
                  
                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'scan_dev_fngr':
                    if node_data['devfngr-target']:
                        params = {'target': node_data['devfngr-target']}

                    if node_data['devfngr-fplimit'] == 'n':
                        params['limit'] = False

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'scan_full':
                    params = {}
                    if node_data['full-target']:
                        params['target'] = node_data['full-target']

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'scan_snmp':
                    params = {}
                    if node_data['snmp-target']:
                        params['target'] = node_data['snmp-target']

                    if node_data['snmp-type']:
                        params['type'] = node_data['snmp-type']

                    if node_data['snmp-scripts']:
                        params['scripts'] = node_data['snmp-scripts']

                    if node_data['snmp-community']:
                        params['community'] = node_data['snmp-community']

                    handler = action_map.get(node_data['name'])     
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'scan_port':
                    params = {}
                    if node_data['port-target']:
                        params['target'] = node_data['port-target']

                    if node_data['port-options']:
                        params['ports'] = node_data['port-options']

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'test_srvr':
                    params = {}
                    if node_data['perfs-options']:
                        params['options'] = node_data['perfs-options']

                    if node_data['perfs-bind']:
                        params['host'] = node_data['perfs-bind']

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'test_clnt':
                    params = {}
                    if node_data['perfc-options']:
                        params['options'] = node_data['perfc-options']

                    if node_data['perfc-server']:
                        params['server'] = node_data['perfc-server']

                    if node_data['perfc-bind']:
                        params['host'] = node_data['perfc-bind']

                    handler = action_map.get(node_data['name']) 
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'trcrt':
                    params = {}
                    if node_data['trcrt-options']:
                        params['options'] = node_data['trcrt-options']

                    if node_data['trcrt-target']:
                        params['target'] = node_data['trcrt-target']

                    if node_data['trcrt-pktlen']:
                        params['packetlen'] = node_data['trcrt-pktlen']

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'trcrt_dns':
                    params = {}
                    if node_data['trcrtdns-options']:
                        params['options'] = node_data['trcrtdns-options']

                    if node_data['trcrtdns-target']:
                        params['target'] = node_data['trcrtdns-target']

                    if node_data['tracrtdns-server']:
                        params['server'] = node_data['tracrtdns-server']

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'pcap_lcl':
                    params = {}
                    if node_data['pcaplcl-iface']:
                        params['interface'] = node_data['pcaplcl-iface']

                    if node_data['pcaplcl-count']:
                        params['cap_count'] = node_data['pcaplcl-count']

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}
              
                case 'pcap_win' | 'pcap_tux':
                    params = {}
                    if node_data['pcaprm-iface']:
                        params['remote_interface'] = node_data['pcaprm-iface']

                    if node_data['pcaprm-host']:
                        params['host'] = node_data['pcaprm-host']

                    if node_data['pcaprm-user']:
                        params['username'] = node_data['pcaprm-user']

                    if node_data['pcaprm-pass']:
                        params['password'] = node_data['pcaprm-pass']

                    if node_data['pcaprm-duration'] and node_data['name'] == 'pcap_win':
                        params['duration'] = node_data['pcaprm-duration']

                    if node_data['name'] == 'pcap_tux' and node_data['pcaprm-count']:
                        params['cap_count'] = node_data['pcaprm-count']

                    handler = action_map.get(node_data['name'])
                    local_tools_to_execute[node_id] = {'tool': handler, 'prms': params}

                case 'slack':
                    alerts['tool'] = node_data['name']

                case 'jira':
                    alerts['tool'] = node_data['name']
                 
                case 'email':
                    alerts['tool'] = node_data['name']

                case 'smartbot':
                    if node_data['bot-prompt']:
                        agents['prompt'] = node_data['bot-prompt']
                        agents['agent'] = node_data['name']

        if local_tools_to_execute != {}:
            for node_id, tool_info in local_tools_to_execute.items():
                handler = tool_info['tool']
                params = tool_info['prms']
                if handler == 'pcap_tux' or handler == 'pcap_win':
                    pcap.set_host(host=params['host'])
                    pcap.set_credentials(user=params['usr'], password=params['pwd'])

                if handler.startswith("scan_"):
                    cur_dir = os.getcwd()
                    scan_dir = os.path.join(cur_dir, "nmap_scans")
                    if not os.path.exists(scan_dir):
                                            os.makedirs(scan_dir)

                    timestamp = datetime.now(tz=timezone.utc).isoformat()
                    exec_name = f"{handler}_result_{timestamp}"
                    file=os.path.join(scan_dir, exec_name)
                    file_name = f"{file}.xml"
                    net_discovery.set_output_file(file_name)

                    if handler == 'scan_snmp' and 'community' in params and params['community']:
                        net_discovery.set_community_string(params['community'])

                    if net_discovery.get_interface() == os.environ.get('DEFAULT_INTERFACE'):
                        params['subnet'] = probe_util.get_interface_subnet(interface=os.environ.get('DEFAULT_INTERFACE'))['network']
                    else:
                        params['subnet'] = probe_util.get_interface_subnet(interface=probe_util.get_ifaces()[0])['network']
                           
                    net_discovery.set_command()
                        
                result = await handler(**params)
                node_output_mapping[node_id]['result'] = result
                node_output_mapping[node_id]['tool'] = handler
                node_output_mapping[node_id]['prb'] = probe_data_dict.get('name')

                timestamp = datetime.now(tz=timezone.utc).isoformat()
                await log_alert.write_log(log_name=f"{handler}_result_{timestamp}", message=result)

        if remote_tools_to_execute != {}:
            for node_id, tool_info in remote_tools_to_execute.items():
                headers = {'content-type': 'application/json',
                           'X-UMJ-WFLW-API-KEY': probe_data_dict.get('umj_api_key')}
                
                handler = action_map.get('bot')

                bot_data = {'url': probe_data_dict.get('umj_url'), 
                            'headers': headers,
                            'prb': tool_info['prb'],
                            'usr': probe_data_dict.get('assigned_user'),
                            'payload': {
                                    'name': tool_info['name'],
                                    'arguments': tool_info['arguments'],
                                    'prb_id': tool_info['prb'],
                                }
                            }
                
                mcp_run = await handler(**bot_data)

                if mcp_run.status_code == 200:
                    mcp_tool_data = mcp_run.json()
                    if node_id in node_output_mapping and node_output_mapping[node_id]:
                        node_output_mapping[node_id]['result'] = mcp_tool_data['output']
                        node_output_mapping[node_id]['prb'] = remote_tools_to_execute[node_id]['prb']
                        node_output_mapping[node_id]['tool'] = bot_data['payload']['name']

        return node_output_mapping, alerts, agents