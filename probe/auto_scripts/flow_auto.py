import asyncio
import argparse
from websockets.asyncio.client import connect
import json
from FlowRunner import FlowRunner
from probe.init_app import logger

async def run_flow(flow: str, ws_url: str, probe_data: str, flow_name: str):
    flow_runner = FlowRunner()
    tool_output, alerts, agents = await flow_runner.run(flow_str=flow)
    probe_data_dict = json.loads(probe_data)

    tool_outputs = "\n\n".join([f"Probe: {output['prb']} \n\n{output['tool']} Output:\n{output['result']}" for output in tool_output])
    logger.info(f"Tool outputs: {tool_outputs}")
    
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