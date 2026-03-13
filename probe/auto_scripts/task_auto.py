from datetime import datetime
import asyncio
import argparse
from datetime import datetime, timezone
from websockets.asyncio.client import connect
import json
from probe.init_app import log_alert
from script_base.base import run_task, parse_scan_results

async def automate_task(action: str, params: str, ws_url: str, probe_data: str, llm_data: str = None, snmp_community: str = None):
    async with connect(uri=ws_url) as websocket:
        code, output, error, file_name = await run_task(action=action, params=params, snmp_community=snmp_community)

        result = await parse_scan_results(action=action, file_name=file_name, probe_data_dict=json.loads(probe_data), params_dict=json.loads(params), output=output)

        log_message=f""
        log_message+=f"{code}\n\n"
        log_message+=f"{output}\n\n"
        log_message+=f"{error}"

        timestamp = datetime.now(tz=timezone.utc).isoformat()

        await log_alert.write_log(log_name=f"{action}_result_{timestamp}", message=log_message)

        probe_data_dict = json.loads(probe_data)
        smartbot_data = json.loads(llm_data) if llm_data is not None else None
       
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

    asyncio.run(automate_task(action=args.action, params=args.params, ws_url=args.ws_url, probe_data=args.probe_data, llm_data=args.llm_data, snmp_community=args.snmp_community))