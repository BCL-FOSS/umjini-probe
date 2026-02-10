import logging
import ast
import json
import httpx
from quart import jsonify
from init_app import logger
import os
import uuid
import ast

# Headers and payloads to initialize MCP server connections
headers = {
    'accept': 'application/json, text/event-stream',
    'content-type': 'application/json'
}

init_payload = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-08-24",
        "capabilities": {},
        "clientInfo": {
            "name": "python-client",
            "version": "1.0.0"
        }
    },
    "id": 1
}

init_complete_payload = {
    "jsonrpc": "2.0",
    "method": "notifications/initialized"
}


class FlowRunner:
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.logger = logging.getLogger(__name__)

    # === Defensive parser for MCP arguments ===
    def normalize_arguments(self, args):
        """
        Ensure arguments are always a dict of values (per OpenAI tool spec).
        If model echoes a schema, convert required keys to placeholders.
        """
        if isinstance(args, dict):
            self.logger.debug(f"Using arguments as-is: {args}")
            return args
        elif isinstance(args, list) and len(args) > 0 and isinstance(args[0], dict):
            schema_obj = args[0]
            clean_args = {}
            for req in schema_obj.get("required", []):
                clean_args[req] = f"<missing:{req}>"
            self.logger.warning(f"Model returned schema instead of values. Converted to placeholders: {clean_args}")
            return clean_args
        else:
            self.logger.warning(f"Unexpected arguments format: {args}")
            return {}
        
    async def flow_call_mcp(self, server_url: str, tool_call: dict, mcp_headers: dict):
        """
        Call the FastMCP server tool with sanitized arguments.
        """
        tool_name = tool_call.get("name")
        args = self.normalize_arguments(tool_call.get("arguments", {}))
        self.logger.info(f"Calling MCP tool `{tool_name}` with arguments: {args}")

        async with httpx.AsyncClient() as client:
            # Initialize MCP session
            resp = await client.post(server_url, json=init_payload, headers=mcp_headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))
            
            session_id = resp.headers.get('mcp-session-id')
            mcp_headers['Mcp-Session-Id'] = session_id
            self.logger.info(f"Using MCP session: {session_id}")

            # Complete initialization
            init_complete_resp = await client.post(server_url, json=init_complete_payload, headers=mcp_headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))
            

            # Perform tool call
            tool_call_payload = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": args
                },
                "id": 2
            }

            tool_call_resp = await client.post(server_url, json=tool_call_payload, headers=mcp_headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

            # Extract SSE "data:" line
            lines = tool_call_resp.text.split('\n')
            data_line = next((line for line in lines if line.startswith('data: ')), None)
            if data_line:
                result = json.loads(data_line[6:])
                answer = result['result']['content'][0]
                #answer_data = json.loads(answer['text'])
                text = answer.get("text")
                answer_data = json.loads(text)
                #answer_data_parsed = ast.literal_eval(answer_data)
                self.logger.info(answer_data)
                #await resp.aclose()
                #await init_complete_resp.aclose()
                #await tool_call_resp.aclose()
                return answer_data

    async def run(self, flow_data: dict):
        agents = []
        llm_agents = {}
        agent_count = 0
        static_graph = []
        flow_str = flow_data.get('flow')
        # Convert the string into a dict safely
        # Because it uses single quotes, we can use `ast.literal_eval`
        flow_dict = ast.literal_eval(flow_str)

        # Parsed flow data
        workflow = flow_dict
        self.logger.info(workflow)
        workflow_data = workflow['drawflow']['Home']['data']
        self.logger.info(workflow_data)

        # Node output mapping for llmagent summarization/alert execution
        node_output_mapping = {}
        node_input_mapping = {}
        supervisor_connection_instructions = ""
                
        for node_id, node in workflow_data.items():
            node_data = node.get('data')
            inputs = node.get('inputs')
            outputs = node.get('outputs')

            if outputs != {}:
                for key, value in outputs.items():
                    if value.get('connections') != []:
                        for connection in value.get('connections'):
                            node_output_mapping[node_id] = {'output': connection['node']}

            if inputs != {}:
                for key, value in inputs.items():
                    if value.get('connections') != []:
                        for connection in value.get('connections'):
                            node_input_mapping[node_id] = {'input': connection['node']}

            match node_data['type']:
                    case 'mcp':
                        secondary_probe = await cl_data_db.get_all_data(match=f'*{node_data['name']}*')
                        if secondary_probe is not None:
                            secondary_probe_key=next(iter(secondary_probe))
                            inner_secondary_probe_data=secondary_probe[secondary_probe_key]
                            url = inner_secondary_probe_data['url']
                            secondary_mcp_url = f'{url}/llm/mcp'
                        
                            primary_args = {}
                            secondary_args = {}

                            primary_tool_data = {}
                            secondary_tool_data = {}

                            primary_probe_headers = {
                                'accept': 'application/json, text/event-stream',
                                'content-type': 'application/json',
                                'x-api-key': inner_probe_data['prb_api_key']
                            }

                            secondary_probe_headers = {
                                'accept': 'application/json, text/event-stream',
                                'content-type': 'application/json',
                                'x-api-key': inner_secondary_probe_data['prb_api_key']
                            }

                            if node_data['mcptool'] == 'iperf_c':
                                # Server Settings
                                primary_tool_data['name'] = 'speedtest_server'
                                
                                if node_data['spdsoptions'] is not None or "".strip():
                                    primary_args['options'] = node_data['spdsoptions']
                                
                                if node_data['spdshost'] is not None or "".strip():
                                    primary_args['host'] = node_data['spdshost']

                                primary_tool_data['arguments'] = primary_args

                                # Client Settings
                                secondary_tool_data['name'] = 'speedtest_client'

                                if node_data['spdcserver'] is not None or "".strip():
                                    secondary_args['server'] = node_data['spdcserver']
                                
                                if node_data['spdcoptions'] is not None or "".strip():
                                    secondary_args['options'] = node_data['spdcoptions']
                                
                                if node_data['spdchost'] is not None or "".strip():
                                    secondary_args['host'] = node_data['spdchost']

                                secondary_tool_data['arguments'] = secondary_args

                                tool_params = {
                                    "flow_call_mcp": [
                                        {
                                            "tool_call": primary_tool_data,
                                            "server_url": mcp_url,
                                            "mcp_headers": primary_probe_headers,
                                        },
                                        {
                                            "tool_call": secondary_tool_data,
                                            "server_url": secondary_mcp_url,
                                            "mcp_headers": secondary_probe_headers,
                                        }
                                    ]
                                }

                            if node_data['mcptool'] == 'iperf_s':
                                # Server Settings
                                secondary_tool_data['name'] = 'speedtest_server'
                                
                                if node_data['spdsoptions'] is not None or "".strip():
                                    secondary_args['options'] = node_data['spdsoptions']
                                
                                if node_data['spdshost'] is not None or "".strip():
                                    secondary_args['host'] = node_data['spdshost']

                                secondary_tool_data['arguments'] = secondary_args

                                # Client Settings
                                primary_tool_data['name'] = 'speedtest_client'

                                if node_data['spdcserver'] is not None or "".strip():
                                    primary_args['server'] = node_data['spdcserver']
                                
                                if node_data['spdcoptions'] is not None or "".strip():
                                    primary_args['options'] = node_data['spdcoptions']
                                
                                if node_data['spdchost'] is not None or "".strip():
                                    primary_args['host'] = node_data['spdchost']

                                primary_tool_data['arguments'] = primary_args

                                tool_params = {
                                    "flow_call_mcp": [
                                        {
                                            "tool_call": secondary_tool_data,
                                            "server_url": secondary_mcp_url,
                                            "mcp_headers": secondary_probe_headers,
                                        },
                                        {
                                            "tool_call": primary_tool_data,
                                            "server_url": mcp_url,
                                            "mcp_headers": primary_probe_headers,
                                        }
                                    ]
                                }

                            if node_data['mcptool'] == 'trct_tar':
                                primary_tool_data['name'] = 'traceroute'

                                primary_args['target'] = secondary_probe.get('url')

                                if node_data['trcoptions'] is not None or "".strip():
                                    primary_args['options'] = node_data['trcoptions']

                                if node_data['packetlen'] is not None or "".strip():
                                    primary_args['packetlength'] = node_data['packetlen']

                                primary_tool_data['arguments'] = primary_args

                                tool_params = {
                                    "flow_call_mcp": [
                                        {
                                            "tool_call": primary_tool_data,
                                            "server_url": mcp_url,
                                            "mcp_headers": primary_probe_headers,
                                        }
                                    ]
                                }

                            if node_data['mcptool'] == 'dnstrct_tar':
                                primary_tool_data['name'] = 'traceroute'

                                primary_args['target'] = secondary_probe.get('url')

                                if node_data['trcoptions'] is not None or "".strip():
                                    primary_args['options'] = node_data['trcoptions']

                                if node_data['dnstrcserver'] is not None or "".strip():
                                    primary_args['server'] = node_data['dnstrcserver']

                                primary_tool_data['arguments'] = primary_args

                                
                                tool_params = {
                                    "flow_call_mcp": [
                                        {
                                            "tool_call": primary_tool_data,
                                            "server_url": mcp_url,
                                            "mcp_headers": primary_probe_headers,
                                        }
                                    ]
                                }

                            agents.append(Worker(
                                    name=node_id,
                                    tools={"flow_call_mcp": flow_call_mcp},
                                    tool_params=tool_params
                                )
                            )
                            #agent_count +=1
                    
                    case 'alert':
                        if node_data['name'] == 'jsm':

                            if await cl_data_db.get_all_data(match=f'alrt:jira:*', cnfrm=True) is False:
                                return jsonify({'Create an email alert contact. None currently available.'}), 404

                            if await cl_data_db.get_all_data(match=f'alrt:jira:{node_data['jiraid']}*', cnfrm=True) is False:
                                jira_contact = await cl_data_db.get_all_data(match=f'alrt:jira:1*')
                            else:
                                jira_contact = await cl_data_db.get_all_data(match=f'alrt:jira:{node_data['jiraid']}*')

                            jira_contact_dict=next(iter(jira_contact.values()))

                            jira_alert = JiraSM(cloud_id=jira_contact_dict.get('cloud_id'), auth_email=jira_contact_dict.get('eml'), auth_token=jira_contact_dict.get('token'))

                            tool_key = "jira_send_alert"
                            fields = {
                                "message": "<short summary of the incident or anomaly>",
                                "desc": "<detailed description including metrics/errors>",
                                "note": "<any notes for responders>",
                                "source": "<name of originating system or upstream agent>",
                                "entity": "<affected entity/server>",
                                "alias": "<unique alias for alert>",
                                "priority": "<P1|P2|P3...>",
                                "actions": [],
                                "extra_properties": {},
                            }
                            fallback = {**fields}
                            prompt = f"""You are an alert agent called {node_id} that receives traceroute, dnstraceroute, iperf speedtest and nmap scan results as input. Use your knowledge of network engineering, network administration, firewall configurations, and network security according to NIST, PCI DSS, GDPR, HIPAA and SOC 2 compliance standards to analyze the input for any network misconfigurations, anomalies, errors and security vulnerabilities. If your analysis finds any network misconfigurations, anomalies, errors or security vulnerabilities, build a JIRA alert payload and generate the following fields:
                                - message, desc, note, source, entity, alias, priority, actions, extra_properties
                            Output the JIRA alert payload in the following format:
                                TOOL:jira_send_alert:[{json.dumps(fields)}]
                            Fill each field dynamically from the incoming message/context.
                            If you cannot determine the parameters, output nothing and the fallback configuration will be used.
                            If no network misconfigurations, anomalies, errors or security vulnerabilities are found in the received input data, output:
                                No anomalies, errors or misconfigurations have been identified.
                            """
                            tool_name = {"jira_send_alert": jira_alert.send_alert}

                        if node_data['name'] == 'email':

                            if await cl_data_db.get_all_data(match=f'alrt:eml:*', cnfrm=True) is False:
                                return jsonify({'Create an email alert contact. None currently available.'}), 404
                            
                            if await cl_data_db.get_all_data(match=f'alrt:eml:{node_data['emailid']}*', cnfrm=True) is False:
                                email_contact = await cl_data_db.get_all_data(match=f'alrt:eml:1*')
                            else:
                                email_contact = await cl_data_db.get_all_data(match=f'alrt:eml:{node_data['emailid']}*')
                                
                            email_contact_dict=next(iter(email_contact.values()))

                            email_alert = EmailAlert(host=email_contact_dict.get('host'), port=email_contact_dict.get('port'), username=email_contact_dict.get('user'), password=email_contact_dict.get('pwd'), tls=email_contact_dict.get('tls'), sender=email_contact_dict.get('sender'))

                            tool_key = "email_send_alert"
                            fields = {
                                "subject": "<short summary>",
                                "message": "<detailed description including errors and actions>",
                                "recipient": node_data['emailrecipient'],
                            }
                            fallback = {**fields}
                            prompt = f"""You are an alert agent called {node_id} that receives traceroute, dnstraceroute, iperf speedtest and nmap scan results as input. Use your knowledge of network engineering, network administration, firewall configurations, and network security according to NIST, PCI DSS, GDPR, HIPAA and SOC 2 compliance standards to analyze the input for any network misconfigurations, anomalies, errors and security vulnerabilities. If your analysis finds any network misconfigurations, anomalies, errors or security vulnerabilities, build a EMAIL alert payload and generate the following fields:
                                - subject, message
                            Output the EMAIL alert payload in the following format:
                                TOOL:email_send_alert:[{json.dumps(fields)}]
                            Fill each field dynamically from the incoming message/context.
                            If you cannot determine the parameters, output nothing and the fallback configuration will be used.
                            If no network misconfigurations, anomalies, errors or security vulnerabilities are found in the received input data, output:
                                No anomalies, errors or misconfigurations have been identified.
                        """
                            tool_name = {"email_send_alert": email_alert.send_email_alert}

                        if node_data['name'] == 'slack':

                            if await cl_data_db.get_all_data(match=f'alrt:slack:*', cnfrm=True) is False:
                                return jsonify({'Create a slack alert contact. None currently available.'}), 404
                            
                            if await cl_data_db.get_all_data(match=f'alrt:slack:{node_data['slackid']}*', cnfrm=True) is False:
                                slack_contact = await cl_data_db.get_all_data(match=f'alrt:slack:1*')
                            else:
                                slack_contact = await cl_data_db.get_all_data(match=f'alrt:slack:{node_data['slackid']}*')

                            slack_contact_dict=next(iter(slack_contact.values()))

                            slack_alert = SlackAlert(slack_bot_token=slack_contact_dict.get('token'), slack_channel_id=slack_contact_dict.get('channel_id'))

                            tool_key = "slack_send_alert"
                            fields = {
                                "channel_id": "<slack channel id>",
                                "message": "<detailed alert message>",
                            }
                            fallback = {**fields}
                            prompt = f"""You are an alert agent called {node_id} that receives traceroute, dnstraceroute, iperf speedtest and nmap scan results as input. Use your knowledge of network engineering, network administration, firewall configurations, and network security according to NIST, PCI DSS, GDPR, HIPAA and SOC 2 compliance standards to analyze the input for any network misconfigurations, anomalies, errors and security vulnerabilities. If your analysis finds any network misconfigurations, anomalies, errors or security vulnerabilities, build a SLACK alert payload and generate the following fields:
                                - message
                            Output the SLACK alert payload in the following format:
                                TOOL:slack_send_alert:[{json.dumps(fields)}]
                            Fill each field dynamically from the incoming message/context.
                            If you cannot determine the parameters, output nothing and the fallback configuration will be used.
                            If no network misconfigurations, anomalies, errors or security vulnerabilities are found in the received input data, output:
                                No anomalies, errors or misconfigurations have been identified.
                            """
                            tool_name = {"slack_send_alert": slack_alert.send_alert_message}

                        tool_params = {tool_key: [fallback]}

                        llm_agents[node_id] = LLMWorker(
                                    name=node_id,
                                    model=os.environ.get("OLLAMA_MODEL"),
                                    tools=tool_name,
                                    prompt=prompt,
                                    tool_params=tool_params
                                )
                            
                        #agent_count +=1
                    case 'tool':
                        primary_args = {}
                        primary_tool_data = {}
                        primary_probe_headers = {
                            'accept': 'application/json, text/event-stream',
                            'content-type': 'application/json',
                            'x-api-key': inner_probe_data['prb_api_key']
                        }

                        logger.info(f"Primary probe API key: {inner_probe_data['prb_api_key']}")

                        if node_data['name'] == 'traceroute':
                            if 'target' in node_data and node_data['target'] is not None or "".strip():
                                primary_args['target'] = node_data['target']

                            if 'options' in node_data and node_data['options'] is not None or "".strip():
                                primary_args['options'] = str(node_data['options'])

                            if 'packetlen' in node_data and node_data['packetlen'] is not None or "".strip():
                                primary_args['packetlength'] = str(node_data['packetlen'])

                            primary_tool_data['name'] = node_data['name']
                            primary_tool_data['arguments'] = primary_args

                            tool_params = {
                                    "flow_call_mcp": [
                                        {
                                            "tool_call": primary_tool_data,
                                            "server_url": mcp_url,
                                            "mcp_headers": primary_probe_headers,
                                        }
                                    ]
                                }

                        if node_data['name'] == 'traceroute_dns':
                            if node_data['target'] is not None or "".strip():
                                primary_args['target'] = node_data['target']

                            if node_data['options'] is not None or "".strip():
                                primary_args['options'] = str(node_data['options'])

                            if node_data['server'] is not None or "".strip():
                                primary_args['server'] = str(node_data['server'])

                            primary_tool_data['name'] = node_data['name']
                            primary_tool_data['arguments'] = primary_args

                            tool_params = {
                                    "flow_call_mcp": [
                                        {
                                            "tool_call": primary_tool_data,
                                            "server_url": mcp_url,
                                            "mcp_headers": primary_probe_headers,
                                        }
                                    ]
                                }

                        agents.append(Worker(
                            name=node_id,
                            tools={"flow_call_mcp": flow_call_mcp},
                            tool_params=tool_params
                            )
                        )
                        #agent_count +=1

            """
            advanced_supervisor_prompt = (
                f"You are an AI workflow supervisor for a multi-agent orchestration system managing {agent_count} agents. "
                "Agents may need to run in different orders, with results passed between them, depending on the workflow state. "
                "At each step, decide which agent to run next and what inputs/results to pass. "
                "You must reason about dependencies, results, and overall workflow goals. "
                "Output your orchestration decision as valid JSON: "
                "{\"run_agent\": \"<name>\", \"inputs\": {...}, \"done\": false} "
                "If you are finished, set \"done\": true. "
                "If you cannot reason about next actions, the system will fallback to static connection order."
                f"\nAvailable agents: {', '.join([a.name for a in agents])}\n"
                f"Workflow connection instructions:\n{supervisor_connection_instructions}\n"
                "History and state will be provided at each step."
            )
            """

            logger.info(f"Current workers: {agents}")

            logger.info(static_graph)

            supervisor = Supervisor(
                workers=agents
            )

            result = await supervisor.orchestrate(static_graph=static_graph)
            logger.info(result)

            if node_output_mapping != {}:
                executed_agents = list(result.keys())

                for agent in executed_agents:
                    if node_output_mapping.get(agent) is not None:
                        llm_worker_input=result[agent]['flow_call_mcp'][0][1]
                        llm_agent_result = await llm_agents.get(node_output_mapping.get(agent)).act(incoming_message=llm_worker_input)
                        llm_output_data = llm_agent_result[0]['result']
                        logger.info(llm_output_data)

            #agent_count = 0

       