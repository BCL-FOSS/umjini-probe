import platform
import logging
import asyncio
import subprocess

class Network():
    
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.system = platform.system().lower()
        self.logger = logging.getLogger(__name__)

    async def run_shell_cmd(self, cmd: str):
        process = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()
    
        self.logger.error(stderr.decode())
        
        self.logger.info(stdout.decode())
        
        return_code = await process.wait()  
        
        self.logger.info(return_code)

        return return_code, stdout.decode(), stderr.decode()
    
    async def run_ssh_cmd(self, host: str, user: str, password: str, cmd: str):
        command = (
            f"sshpass -p '{password}' ssh -tt -o StrictHostKeyChecking=no "
            f"{user}@{host} 'bash {cmd}'"
            # f"{user}@{host} 'echo {password} | sudo -S bash /usr/local/bin/ubnt-ssl-config.sh {host}'"
            )
        process = await asyncio.create_subprocess_shell(
            command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()
    
        self.logger.error(stderr.decode())
        
        self.logger.info(stdout.decode())
        
        return_code = await process.wait()  
        
        self.logger.info(return_code)
    
    async def ssh_connect(self, host: str, user: str, password: str):
        command = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=accept-new "
            f"{user}@{host} 'hostname'"
            )
        process = await asyncio.create_subprocess_shell(
            command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()
    
        self.logger.error(stderr.decode())
        
        self.logger.info(stdout.decode())
        
        return_code = await process.wait()  
        
        self.logger.info(return_code) 

   
        