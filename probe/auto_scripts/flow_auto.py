import asyncio
import argparse
from websockets.asyncio.client import connect
import json
from FlowRunner import FlowRunner
from probe.init_app import logger
from script_base.base import run_task, parse_scan_results, send_smartbot_data


async def run_flow(flow: str, ws_url: str, probe_data: str, flow_name: str):
    flow_runner = FlowRunner()
    tool_output, alerts, agents = await flow_runner.run(flow_str=flow)
    probe_data_dict = json.loads(probe_data)
    async with connect(uri=ws_url) as websocket:
        await send_smartbot_data(ws=websocket, probe_data_dict=probe_data_dict, smartbot_data=agents, tool_call_resp=tool_output)
                
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