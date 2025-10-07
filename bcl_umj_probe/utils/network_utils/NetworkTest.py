import os
import platform
import subprocess
import requests
import iperf3
from iperf3 import TestResult
from utils.network_utils.base.Network import Network
from scapy.all import *
from scapy import *
from scapy.tools import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.layers import dns
from scapy.layers.dns import *
import asyncio
from datetime import datetime, timezone

class NetworkTest(Network):
    def __init__(self):
        super().__init__()
    
    async def iperf_server(self, options: str = None, host: str = '0.0.0.0'):
        test_result_file = f'spdtst-server-result-{datetime.now(timezone.utc)}.json'
        pid_file = f'spdtst-server-pid-{datetime.now(timezone.utc)}.txt'
        command = f'iperf3 -s -p 7969 --logfile {test_result_file} --bind {host} - V -J --cport 7968 -D --pidfile {pid_file}'

        if options is not None:
            command += options

        code, output, error = await self.run_shell_cmd(cmd=command)

        return code, output, error
    
    async def iperf_client(self, server: str, options: str = None, host: str = '0.0.0.0'):
        test_result_file = f'spdtst-client-result-{datetime.now(timezone.utc)}.json'
        command = f'iperf3 -c {server} -p 7969 --cport 7968 --bind {host} - V -J --logfile {test_result_file}'

        if options is not None:
            command += options

        code, output, error = await self.run_shell_cmd(cmd=command)

        return code, output, error


    async def traceroute(self, target: str, options: str = None, packetlen: str = None):
        command = f'traceroute '

        if options is not None:
            command += f'{options} '
            self.logger.info(command)
        
        if packetlen is not None:
            command += f'{target} '
            command += packetlen
        else:
            command += target
            self.logger.info(command)

        code, output, error = await self.run_shell_cmd(cmd=command)

        return code, output, error
    
    async def dnstraceroute(self, target: str, server: str = '8.8.8.8', options: str = None):
        command = f'dnstraceroute -s {server} '

        if options is not None:
            command += f'{options} '
            command += target
            self.logger.info(command)
        else:
            command += target
            self.logger.info(command)

        code, output, error = await self.run_shell_cmd(cmd=command)

        return code, output, error
    
    


       
