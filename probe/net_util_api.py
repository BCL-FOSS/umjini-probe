from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Response
from fastapi_user_limiter.limiter import rate_limiter
from pydantic import BaseModel
from init_app import (
    validate_api_key,
    init_probe, logger, prb_db, cron
)
import httpx
from net_util_mcp import mcp
from CoreClientv2 import CoreClient
import asyncio
from auto_scripts.script_base.base import run_task, parse_scan_results, schedule_cronjob
import json
import os
from websockets.asyncio.client import connect
from datetime import datetime, timezone
import re 

class InitCall(BaseModel):
    umj_url: str 
    umj_usr: str
    umj_site: str
    umj_api_key: str
    prb_url: str
    prb_api_key: str
    prb_name: str

class ExecuteCall(BaseModel):
    action: str = None
    params: dict = None

prb_id, hstnm, probe_data = init_probe()
websocket_url = None
if probe_data.get('umj_url'):
    websocket_url = f"websockets://{probe_data.get('umj_url')}/v1/api/core/channels/probe/heartbeat/{probe_data.get('prb_id')}"
logger.info(f"Probe initialized: hostname={hstnm}")
mcp_app = mcp.http_app(path="/mcp")

@asynccontextmanager
async def combined_lifespan(app:FastAPI):
    async with mcp_app.lifespan(app):
        # idempotent guard
        if getattr(app.state, "core_client_started", False) is False and probe_data.get("umj_url"):
            app.state.core_client_started = True
            app.state.core_client = None
            app.state.core_client_task = None
            app.state.core_client_stop = None
            if websocket_url is None:
                logger.warning("WebSocket URL is not set; CoreClient will not be started")
                yield
                return
            core_client = CoreClient(umj_websocket_url=websocket_url)
            stop_event = asyncio.Event()
            app.state.core_client_stop = stop_event
            app.state.core_client = core_client
            app.state.core_client_task = asyncio.create_task(core_client.run(stop_event))
            logger.info("Started CoreClient task in FastAPI lifespan")
        
        yield
        
        stop_event = getattr(app.state, "core_client_stop", None)
        task = getattr(app.state, "core_client_task", None)

        if stop_event is not None:
            stop_event.set()

        if task is not None:
            try:
                await asyncio.wait_for(task, timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning("CoreClient task did not exit in time; cancelling")
                task.cancel()
                try:
                    await task
                except Exception:
                    pass

            logger.info("CoreClient stopped and combined_lifespan exiting")

api = FastAPI(title='Network Util API', lifespan=combined_lifespan)

async def _make_http_request(cmd: str, url: str, payload: dict = {}, headers: dict = {}, cookies: str = ''):
    async with httpx.AsyncClient() as client:
        if cmd == 'p':
            client.cookies.set("access_token", value=cookies)
            return await client.post(url, json=payload, headers=headers)
        elif cmd == 'g':
            return await client.get(url, headers=headers)
        
@api.get("/v1/api/status", dependencies=[Depends(rate_limiter(2, 5)), Depends(validate_api_key)])
def status():
    return Response(content='{"status": "ok"}', media_type="application/json", status_code=200)

@api.post("/v1/api/init", dependencies=[Depends(validate_api_key), Depends(rate_limiter(2, 5))])
async def init(init_data: InitCall):
    init_url = f"https://{init_data.umj_url}/init?usr={init_data.umj_usr}"
    logger.info(init_url)
    enroll_url = f"https://{init_data.umj_url}/enroll?usr={init_data.umj_usr}&site={init_data.umj_site}"
    logger.info(enroll_url)

    async def enrollment(payload: dict = {}):
        headers = {"X-UMJ-WFLW-API-KEY": init_data.umj_api_key}
        post_headers = {"X-UMJ-WFLW-API-KEY": init_data.umj_api_key,
                        "Content-Type": "application/json"}

        resp_data = await _make_http_request(cmd="g", url=init_url, headers=headers)
        if resp_data.status_code == 200:
            access_token = resp_data.cookies.get("access_token")
            logger.info(access_token)
            enroll_rqst = await _make_http_request(
                cmd="p",
                url=enroll_url,
                headers=post_headers,
                cookies=access_token,
                payload=payload,
            )
            return 200 if enroll_rqst.status_code == 200 else 400
        return None
    
    await prb_db.connect_db()

    probe_data['url'] = init_data.prb_url
    probe_data['prb_api_key'] = init_data.prb_api_key
    probe_data['site'] = init_data.umj_site
    probe_data['name'] = init_data.prb_name
    probe_data['assigned_user'] = init_data.umj_usr
    logger.info(probe_data)

    if await enrollment(payload=probe_data) != 200:
        return Response(content='{"Error": "occurred during probe adoption"}', media_type="application/json", status_code=400)
    else:
        probe_info = await prb_db.get_all_data(match=f"prb-*")
        probe_info_dict = next(iter(probe_info.values()))
        probe_id = probe_info_dict.get('prb_id')

        probe_data['umj_url'] = init_data.umj_url
        probe_data['umj_api_key'] = init_data.umj_api_key
        probe_data.pop('prb_api_key')

        return Response(content='{"status": "ok"}', media_type="application/json", status_code=200) if await prb_db.upload_db_data(id=probe_id, data=probe_data) > 0 else Response(content='{"Error": "occurred during probe adoption"}', media_type="application/json", status_code=400)
        
@api.post("/v1/api/tasks/{command}", dependencies=[Depends(validate_api_key), Depends(rate_limiter(4, 10))])
async def tasks(command: str, tool_call: ExecuteCall = None):
    async with connect(uri=websocket_url) as websocket:
        match command:
            case 'exec':
                code, output, error, file_name = await run_task(action=tool_call.action, params=json.dumps(tool_call.params), snmp_community=tool_call.params.get('community') if 'community' in tool_call.params else None)

                if code == 0:
                    parsed_result = await parse_scan_results(action=tool_call.action, file_name=file_name, probe_data_dict=probe_data, params_dict=tool_call.params, output=output)
                else:
                    parsed_result = None

                return_data = {
                    "code": code,
                    "output": output,
                    "error": error,
                    "parsed_result": parsed_result
                }
                return Response(content=json.dumps(return_data), media_type="application/json", status_code=200 if code == 0 else 400)
            case 'init':      
                job1 = None
                cwd = os.getcwd() 
                if 'prms' in tool_call.params and tool_call.params['prms']:
                                params = tool_call.params['prms']
                now = datetime.now(tz=timezone.utc).isoformat()
                job_comment=f"auto_job_{probe_data.get('prb_id')}"
                task_command = ""
                script_path = os.path.join(cwd, 'auto_scripts', f'{tool_call.params["auto_type"]}_auto.py')
                                            
                if tool_call.params['auto_type'] == 'task':
                    task_command = f"python3 {script_path} -a {tool_call.params['task']} -p '{json.dumps(params)}' -w {websocket_url} -pdta '{json.dumps(probe_data)}' -llmdta '{json.dumps(tool_call.params.get('llm_data'))}'"

                    if 'community' in tool_call.params and tool_call.params['community']:
                        task_command += f" -snmp {tool_call.params.get('community')}"

                    job_comment+=f"_{tool_call.params['task']}_{now}"

                if tool_call.params['auto_type'] == 'chat':
                    task_command = f"python3 {script_path} -w {websocket_url} -pdta '{json.dumps(probe_data)}' -t '{tool_call.params.get('tool_calls')}' -llmdta '{json.dumps(tool_call.params.get('llm_data'))}'"

                    if 'community' in tool_call.params and tool_call.params['community']:
                                    task_command += f" -snmp {tool_call.params.get('community')}"

                    job_comment+=f"_chat_{now}"
                                
                if tool_call.params['auto_type'] == 'flow':                
                    job_comment+=f"_flow_{tool_call.params['flow_name']}_{now}"

                    task_command = f"python3 {script_path} -f {tool_call.params['flow']} -w {websocket_url} -pdta '{json.dumps(probe_data)}' -n {tool_call.params['flow_name']}"

                    flow_data = {
                                    'id': tool_call.params['id'],
                                    'probe': tool_call.params['probe'],
                                    'flow': tool_call.params['flow'],
                                    'name': tool_call.params['name']
                                }
                    logger.info(f"Uploading flow data: {flow_data}") if await prb_db.upload_db_data(id=tool_call.params['id'], data=flow_data) is not None else logger.error("Failed to upload flow data to RedisDB.")

                job1 = cron.new(command=task_command, comment=job_comment)

                scheduled_job = await asyncio.to_thread(schedule_cronjob, job1, tool_call.params)

                if await asyncio.to_thread(scheduled_job.is_valid):
                    await asyncio.to_thread(cron.write)
                    await asyncio.sleep(1)
                    logger.info(f"Cron job added: {scheduled_job}")
                    await websocket.send(json.dumps({
                        'site': probe_data.get('site'),
                        'task_output': f"{tool_call.params['auto_type']} cron job added to {probe_data.get('name')} at site: {probe_data.get('site')}.",
                        'prb_id': probe_data.get('prb_id'),
                        'prb_name': probe_data.get('name'),
                        'job_type': tool_call.params['auto_type'] if tool_call.params['auto_type'] == 'flow' else f'{tool_call.params['task']}',
                        'job_name': f'cron_job_{job_comment}',
                        'act': "prb_task_cnfrm",
                        'comment': job_comment,
                        'enabled': 'enabled',
                        'storage_opt': 'new',
                        'user_id': tool_call.params['user_id']
                    }))
                else:
                    logger.error("Invalid cron job, not writing to crontab.")
            case 'disable':
                job = await asyncio.to_thread(cron.find_comment, comment=tool_call.params['comment'])
                await asyncio.to_thread(job.enable, False)
                await asyncio.to_thread(cron.write)
                await asyncio.sleep(1)
                tool_call.params['storage_opt'] = 'updt'
                tool_call.params['act'] = 'prb_task_cnfrm'
                tool_call.params['task_output'] = f"Cron job '{tool_call.params['comment']}' disabled."
                await websocket.send(json.dumps(tool_call.params))
            case 'enable':
                job = await asyncio.to_thread(cron.find_comment, comment=tool_call.params['comment'])
                await asyncio.to_thread(job.enable, True)
                await asyncio.to_thread(cron.write)
                await asyncio.sleep(1)
                tool_call.params['storage_opt'] = 'updt'
                tool_call.params['act'] = 'prb_task_cnfrm'
                tool_call.params['task_output'] = f"Cron job '{tool_call.params['comment']}' enabled."
                await websocket.send(json.dumps(tool_call.params))
            case 'remove':
                job = await asyncio.to_thread(cron.find_comment, comment=tool_call.params['comment'])
                await asyncio.to_thread(cron.remove, job)
                await asyncio.to_thread(cron.write)
                await asyncio.sleep(1)
                tool_call.params['act'] = 'prb_task_cnfrm'
                tool_call.params['task_output'] = f"Cron job '{tool_call.params['comment']}' deleted."
                tool_call.params['storage_opt'] = 'del'
                await websocket.send(json.dumps(tool_call.params))
            case 'remove_all':
                await asyncio.to_thread(cron.remove_all)
                await asyncio.to_thread(cron.write)
                await asyncio.sleep(1)
                tool_call.params['act'] = 'prb_task_cnfrm'
                tool_call.params['task_output'] = f"All cron jobs deleted."
                await websocket.send(json.dumps(tool_call.params))
            case 'reschedule':
                job = await asyncio.to_thread(cron.find_comment, comment=tool_call.params['comment'])
                if job:
                    job = await asyncio.to_thread(schedule_cronjob, job, tool_call.params)
                                    
                if await asyncio.to_thread(job.is_valid):
                    await asyncio.to_thread(cron.write)
                    await asyncio.sleep(1)
                    logger.info(f"Cron job rescheduled: {job}")
                    tool_call.params['enabled'] = 'enabled' if job.is_enabled() else 'disabled'
                    tool_call.params['storage_opt'] = 'updt'
                    tool_call.params['act'] = 'prb_task_cnfrm'
                    tool_call.params['task_output'] = f"Cron job '{tool_call.params['comment']}' rescheduled."
                    await websocket.send(json.dumps(tool_call.params))
            case 'list':
                all_tasks = []
                for job in cron:
                    if job.comment.startswith(f"auto_job_{probe_data.get('prb_id')}"):
                        task_info = {
                            "comment": job.comment,
                            "schedule": str(job.slices),
                            "command": job.command,
                            "enabled": job.is_enabled()
                        }
                        all_tasks.append(task_info)

                return Response(content=json.dumps(all_tasks), media_type="application/json", status_code=200) if all_tasks != [] else Response(content='{"status": "no tasks found"}', media_type="application/json", status_code=400)

@api.get("/v1/api/flows/{command}", dependencies=[Depends(validate_api_key), Depends(rate_limiter(4, 10))])
async def flows(command: str, tool_call: ExecuteCall = None):
    match command:
        case 'list':
            all_flows = await prb_db.get_all_data(match=f"flow:*")
            all_flows_dict = next(iter(all_flows.values())) if all_flows is not None else None
          
            return Response(content=json.dumps(all_flows_dict), media_type="application/json", status_code=200) if all_flows_dict is not None else Response(content='{"status": "no flows found"}', media_type="application/json", status_code=400)     
        case 'delete':
            result = await prb_db.del_obj(key=tool_call.params['id'])
            return Response(content='{"status": "flow deleted"}', media_type="application/json", status_code=200) if result is not None else Response(content='{"status": "flow deletion failed"}', media_type="application/json", status_code=400)
        case 'new':
            flow_data = {
                'id': tool_call.params.get('id'),
                'probe': tool_call.params.get('probe'),
                'flow': tool_call.params.get('flow'),
                'name': tool_call.params.get('name')
            }
            result = await prb_db.upload_db_data(id=tool_call.params.get('id'), data=flow_data)

            return Response(content='{"status": "flow created"}', media_type="application/json", status_code=200) if result is not None else Response(content='{"status": "flow creation failed"}', media_type="application/json", status_code=400)
        case 'load':
            flow = await prb_db.get_all_data(match=f"*{tool_call.params.get('id')}*")
            flow_data = next(iter(flow.values())) if flow is not None else None

            return Response(content=json.dumps(flow_data), media_type="application/json", status_code=200) if flow_data is not None else Response(content='{"status": "flow load failed"}', media_type="application/json", status_code=400)
        case 'edit':
            result = await prb_db.upload_db_data(id=tool_call.params.get('id'), data=tool_call.params)

            return Response(content='{"status": "flow edited"}', media_type="application/json", status_code=200) if result is not None else Response(content='{"status": "flow edit failed"}', media_type="application/json", status_code=400)
