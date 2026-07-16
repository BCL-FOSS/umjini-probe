from datetime import datetime
import asyncio
import argparse
from datetime import datetime, timezone
from websockets.sync.client import connect
import json
from probe.init_app import log_alert
from script_base.base import run_task, parse_scan_results

async def automate_task(tools_to_execute: list[dict], ws_url: str, probe_id: str):
    async with connect(uri=ws_url) as websocket:
        log_message = ""
        for tool in tools_to_execute:
            action = tool.get('action')
            params = tool.get('prms')
            snmp_community = params.get('community') if 'community' in params else None
            timestamp = datetime.now(tz=timezone.utc).isoformat()
            code, output, error, file_name = await run_task(action=action, params=params, snmp_community=snmp_community)
            result = await parse_scan_results(action=action, file_name=file_name, probe_id=probe_id, params_dict=json.loads(params), output=output)
            tool['output'] = output
            tool['parsed'] = result
            tool['timestamp'] = timestamp
            log_message+=f"Code: {code}\nOutput: {output}\nError: {error}\n\n" 
        await log_alert.write_log(log_name=f"{action}_result_{datetime.now(tz=timezone.utc).isoformat()}", message=log_message)
        websocket.send(json.dumps({'act': 'ingest','prbid': probe_id, 'data': json.dumps(tools_to_execute)}))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate network monitoring tasks.")
    parser.add_argument(
        '-t', '--tasks', 
        type=str, 
        help="Network task to perform"
    )
   
    parser.add_argument(
        '-w', '--ws_url', 
        type=str, 
        help="WebSocket URL for reporting results"
    )
    parser.add_argument(
        '-pid', '--probe_id', 
        type=str, 
        help="Probe ID for reporting results"
    )
    args = parser.parse_args()

    asyncio.run(automate_task(tools_to_execute=json.loads(args.tasks), ws_url=args.ws_url, probe_id=args.probe_id))