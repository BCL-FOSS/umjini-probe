import datetime
import ast
from datetime import datetime, timezone
from probe.init_app import action_map, log_alert, probe_util, net_discovery, logger, prb_db
from script_base.base import run_task
import json

class FlowRunner:
    def __init__(self):
        self.logger = logger
        self.prb_db = prb_db

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
                            remote_tool_params['tool_prms']['options'] = node_data['prb-trcrtoptions']
                        if node_data['prb-trcrtpktlen']:
                            remote_tool_params['tool_prms']['packetlen'] = node_data['prb-trcrtpktlen']
                        if node_data['prb-trcrtdnsserver'] and node_data['prb-trcrttype'] == 'trcrt_dns':
                            remote_tool_params['tool_prms']['server'] = node_data['prb-trcrtdnsserver']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-trcrttype'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                    if node_data['prb-perftype']:

                        if node_data['prb-perfoptions']:
                            remote_tool_params['tool_prms']['options'] = node_data['prb-perfoptions']
                        if node_data['prb-perfserver'] and node_data['prb-perftype'] == 'spdtst_clnt':
                            remote_tool_params['tool_prms']['server'] = node_data['prb-perfserver']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-perftype'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                    if node_data['prb-scanstype']:
                        if node_data['prb-scantarget']:
                            remote_tool_params['tool_prms']['target'] = node_data['prb-scantarget']

                        if node_data['prb-scandevidnoise'] == 'n' and node_data['prb-scanstype'] == 'scan_dev_id':
                            remote_tool_params['tool_prms']['limit'] = False

                        if node_data['prb-scanfplimit'] == 'y' and node_data['prb-scanstype'] == 'scan_dev_fngr':
                            remote_tool_params['tool_prms']['noise'] = True

                        if node_data['prb-scansnamptype'] and node_data['prb-scanstype'] == 'scan_snmp':
                            remote_tool_params['tool_prms']['type'] = node_data['prb-scansnamptype']

                        if node_data['prb-snmpscanscripts'] and node_data['prb-scanstype'] == 'scan_snmp':
                            remote_tool_params['tool_prms']['scripts'] = node_data['prb-snmpscanscripts']

                        if node_data['prb-snmpcommunity'] and node_data['prb-scanstype'] == 'scan_snmp':
                            remote_tool_params['community'] = node_data['prb-snmpcommunity']

                        if node_data['prb-scanoptions']:
                            remote_tool_params['tool_prms']['options'] = node_data['prb-scanoptions']

                        if node_data['prb-scanports'] and node_data['prb-scanstype'] == 'scan_port':
                            remote_tool_params['tool_prms']['ports'] = node_data['prb-scanports']

                        if node_data['prb-scantgtifacedef'] == 'y' and node_data['scantgtiface']:
                            remote_tool_params['interface'] = node_data['prb-scantgtiface']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-scanstype'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                    if node_data['prb-pcapmode']:
                        if node_data['prb-pcapmode'] != 'pcap_lcl' and node_data['prb-pcaptrmuser'] and node_data['prb-pcaptrmpass'] and node_data['prb-pcaptrmhost']:
                            remote_tool_params['tool_prms']['usr'] = node_data['prb-pcaptrmuser']
                            remote_tool_params['tool_prms']['pwd'] = node_data['prb-pcaptrmpass']
                            remote_tool_params['tool_prms']['host'] = node_data['prb-pcaptrmhost']

                        if node_data['prb-pcapmode'] == 'pcap_lcl' and node_data['prb-pcapcount']:
                            remote_tool_params['tool_prms']['cap_count'] = node_data['prb-pcapcount']

                        if node_data['prb-pcapduration'] and node_data['prb-pcapmode'] == 'pcap_win':
                            remote_tool_params['tool_prms']['duration'] = node_data['prb-pcapduration']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-pcapmode'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                case 'scans':
                    params = {}
                    if node_data['scan-type']:
                        local_tools_to_execute[node_id]['tool'] = node_data['scan-type']

                    if node_data['scan-target']:
                        params['tool_prms']['target'] = node_data['scan-target']

                    if node_data['scan-useiface'] == 'n' and node_data['scan-iface']:
                        params['interface'] = node_data['scan-iface']

                    if node_data['scan-fplimit'] == 'y' and node_data['scan-type'] == 'scan_dev_fngr':
                        params['tool_prms']['limit'] = False

                    if node_data['scan-devidnoise'] == 'n' and node_data['scan-type'] == 'scan_dev_id':
                        params['tool_prms']['noise'] = True

                    if node_data['scan-snmpscripts'] and node_data['scan-type'] == 'scan_snmp':
                        params['tool_prms']['scripts'] = node_data['scan-snmpscripts']

                    if node_data['scan-snmpcommunity'] and node_data['scan-type'] == 'scan_snmp':
                        params['community'] = node_data['scan-snmpcommunity']

                    if node_data['scan-options']:
                        params['tool_prms']['options'] = node_data['scan-options']

                    if node_data['scan-ports'] and node_data['scan-type'] == 'scan_port':
                        params['tool_prms']['ports'] = node_data['scan-ports']

                    local_tools_to_execute[node_id]['prms'] = params

                case 'pcaps':
                    params = {}
                    if node_data['pcap-mode']:
                        local_tools_to_execute[node_id]['tool'] = node_data['pcap-mode']

                    if node_data['pcap-useiface'] == 'n' and node_data['pcap-iface'] and node_data['pcap-mode'] == 'pcap_lcl':
                        params['interface'] = node_data['pcap-iface']

                    if (node_data['pcap-rmhost'] and node_data['pcap-rmuser'] and node_data['pcap-rmpass'] and node_data['pcap-rmiface']) and node_data['pcap-mode'] != 'pcap_lcl':
                        params['tool_prms']['host'] = node_data['pcap-rmhost']
                        params['tool_prms']['usr'] = node_data['pcap-rmuser']
                        params['tool_prms']['pwd'] = node_data['pcap-rmpass']
                        params['tool_prms']['remote_interface'] = node_data['pcap-rmiface']

                    if node_data['pcap-duration'] and node_data['pcap-mode'] == 'pcap_win':
                        params['tool_prms']['duration'] = node_data['pcap-duration']

                    if node_data['pcap-count'] and (node_data['pcap-mode'] == 'pcap_lcl' or node_data['pcap-mode'] == 'pcap_tux'):
                        params['tool_prms']['cap_count'] = node_data['pcap-count']

                    local_tools_to_execute[node_id]['prms'] = params

                case 'test_srvr':
                    params = {}
                    if node_data['perfs-options']:
                        params['tool_prms']['options'] = node_data['perfs-options']

                    if node_data['perfs-bind']:
                        params['tool_prms']['host'] = node_data['perfs-bind']

                    local_tools_to_execute[node_id] = {'tool': node_data['name'], 'prms': params}

                case 'test_clnt':
                    params = {}
                    if node_data['perfc-options']:
                        params['tool_prms']['options'] = node_data['perfc-options']

                    if node_data['perfc-server']:
                        params['tool_prms']['server'] = node_data['perfc-server']

                    if node_data['perfc-bind']:
                        params['tool_prms']['host'] = node_data['perfc-bind']

                    local_tools_to_execute[node_id] = {'tool': node_data['name'], 'prms': params}

                case 'trcrt':
                    params = {}
                    if node_data['trcrt-options']:
                        params['tool_prms']['options'] = node_data['trcrt-options']

                    if node_data['trcrt-target']:
                        params['tool_prms']['target'] = node_data['trcrt-target']

                    if node_data['trcrt-pktlen']:
                        params['tool_prms']['packetlen'] = node_data['trcrt-pktlen']

                    local_tools_to_execute[node_id] = {'tool': node_data['name'], 'prms': params}

                case 'trcrt_dns':
                    params = {}
                    if node_data['trcrtdns-options']:
                        params['tool_prms']['options'] = node_data['trcrtdns-options']

                    if node_data['trcrtdns-target']:
                        params['tool_prms']['target'] = node_data['trcrtdns-target']

                    if node_data['tracrtdns-server']:
                        params['tool_prms']['server'] = node_data['tracrtdns-server']

                    local_tools_to_execute[node_id] = {'tool': node_data['name'], 'prms': params}

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
                code, output, error, file_name = await run_task(action=tool_info['tool'], params=json.dumps(tool_info['prms']), snmp_community=tool_info['prms'].get('community') if 'community' in tool_info['prms'] else None)

                node_output_mapping[node_id]['result'] = output
                node_output_mapping[node_id]['tool'] = tool_info['tool']
                node_output_mapping[node_id]['prb'] = probe_data_dict.get('name')

                timestamp = datetime.now(tz=timezone.utc).isoformat()
                await log_alert.write_log(log_name=f"{tool_info['tool']}_result_{timestamp}", message=output)

        if remote_tools_to_execute != {}:
            for node_id, tool_info in remote_tools_to_execute.items():
                headers = {'content-type': 'application/json',
                           'X-UMJ-WFLW-API-KEY': probe_data_dict.get('umj_api_key')}
                
                handler = action_map.get('bot')

                bot_data = {'url': probe_data_dict.get('umj_url'), 
                            'headers': headers,
                            'usr': probe_data_dict.get('assigned_user'),
                            'payload': {
                                    'tool': tool_info['name'],
                                    'tool_prms': tool_info['arguments'],
                                    'prb_id': tool_info['prb'],
                                }
                            }
                
                mcp_run = await handler(**bot_data)

                if mcp_run.status_code == 200:
                    mcp_tool_data = mcp_run.json()
                    if node_id in node_output_mapping and node_output_mapping[node_id]:
                        node_output_mapping[node_id]['result'] = mcp_tool_data['output']
                        node_output_mapping[node_id]['prb'] = remote_tools_to_execute[node_id]['prb']
                        node_output_mapping[node_id]['tool'] = bot_data['payload']['tool']

        return node_output_mapping, alerts, agents