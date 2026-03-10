import asyncio
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType
from utils.network_utils.base.Network import Network
import asyncio
from bs4 import BeautifulSoup
import httpx
from collections import deque
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv

class NetworkSNMP(Network):
    def __init__(self, host: str='', user: str ='', auth_key: str='', priv_key: str='',
                 auth_protocol=None, priv_protocol=None, port=161):
        # SNMP community string and version
        self.SNMP_COMMUNITY = 'public'
        self.MGR_PORT = 162
        self.AGNT_PORT = 161
        self.SNMP_TRAP_HOST = 'monitor.baughcl.com'
        self.TIMEOUT = 1
        self.RETRIES = 1
        self.trap_log = deque(maxlen=100)  # Store recent traps in memory
        self.OIDS = {
            "uptime": '1.3.6.1.2.1.1.3.0',
            "cpu_idle": '1.3.6.1.4.1.2021.11.10.0',
            "mem_total": '1.3.6.1.4.1.2021.4.5.0',
            "mem_avail": '1.3.6.1.4.1.2021.4.6.0',
            "disk_total": '1.3.6.1.4.1.2021.9.1.6.1',
            "disk_avail": '1.3.6.1.4.1.2021.9.1.7.1',
            "if_descr": '1.3.6.1.2.1.2.2.1.2',
            "if_speed": '1.3.6.1.2.1.2.2.1.5',
            "if_in_errors": '1.3.6.1.2.1.2.2.1.14',
            "if_out_errors": '1.3.6.1.2.1.2.2.1.20',
            "if_in_octets": '1.3.6.1.2.1.2.2.1.10',
            "if_out_octets": '1.3.6.1.2.1.2.2.1.16',
            "if_in_packets": '1.3.6.1.2.1.2.2.1.11', 
            "if_out_packets": '1.3.6.1.2.1.2.2.1.17',
        }
        self.NEW_OIDS = {
            # System
            "uptime": "1.3.6.1.2.1.1.3.0",
            "hostname": "1.3.6.1.2.1.1.5.0",
            "contact": "1.3.6.1.2.1.1.4.0",
            "location": "1.3.6.1.2.1.1.6.0",

            # CPU
            "cpu_idle": "1.3.6.1.4.1.2021.11.11.0",
            "cpu_system": "1.3.6.1.4.1.2021.11.10.0",
            "cpu_user": "1.3.6.1.4.1.2021.11.9.0",
            "cpu_load_1min": "1.3.6.1.4.1.2021.10.1.3.1",
            "cpu_load_5min": "1.3.6.1.4.1.2021.10.1.3.2",
            "cpu_load_15min": "1.3.6.1.4.1.2021.10.1.3.3",

            # Memory
            "mem_total_real": "1.3.6.1.4.1.2021.4.5.0",
            "mem_avail_real": "1.3.6.1.4.1.2021.4.6.0",
            "mem_total_swap": "1.3.6.1.4.1.2021.4.3.0",
            "mem_avail_swap": "1.3.6.1.4.1.2021.4.4.0",
            "mem_buffer": "1.3.6.1.4.1.2021.4.14.0",
            "mem_cached": "1.3.6.1.4.1.2021.4.15.0",

            # Disk
            "disk_path": "1.3.6.1.4.1.2021.9.1.2",
            "disk_device": "1.3.6.1.4.1.2021.9.1.3",
            "disk_total": "1.3.6.1.4.1.2021.9.1.6",
            "disk_avail": "1.3.6.1.4.1.2021.9.1.7",
            "disk_used": "1.3.6.1.4.1.2021.9.1.8",
            "disk_percent": "1.3.6.1.4.1.2021.9.1.9",

            # Interfaces
            "if_number": "1.3.6.1.2.1.2.1.0",
            "if_descr": "1.3.6.1.2.1.2.2.1.2",
            "if_type": "1.3.6.1.2.1.2.2.1.3",
            "if_speed": "1.3.6.1.2.1.2.2.1.5",
            "if_admin_status": "1.3.6.1.2.1.2.2.1.7",
            "if_oper_status": "1.3.6.1.2.1.2.2.1.8",
            "if_in_octets": "1.3.6.1.2.1.2.2.1.10",
            "if_in_ucast_pkts": "1.3.6.1.2.1.2.2.1.11",
            "if_in_errors": "1.3.6.1.2.1.2.2.1.14",
            "if_out_octets": "1.3.6.1.2.1.2.2.1.16",
            "if_out_ucast_pkts": "1.3.6.1.2.1.2.2.1.17",
            "if_out_errors": "1.3.6.1.2.1.2.2.1.20",

            # Host resources
            "hr_storage_descr": "1.3.6.1.2.1.25.2.3.1.3",
            "hr_storage_size": "1.3.6.1.2.1.25.2.3.1.5",
            "hr_storage_used": "1.3.6.1.2.1.25.2.3.1.6",
            "hr_processor_load": "1.3.6.1.2.1.25.3.3.1.2"
        }

    async def get(self, oid: str, host: str):
        snmpEngine = SnmpEngine()
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            CommunityData("public"),
            await UdpTransportTarget.create((host, self.AGNT_PORT)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        if errorIndication:
            print(errorIndication)
        elif errorStatus:
            print(
                "{} at {}".format(
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                )
            )
        else:
            for varBind in varBinds:
                print(" = ".join([x.prettyPrint() for x in varBind]))

    async def walk(self, varBinds, host: str):
        snmpEngine = SnmpEngine()
        while True:
            errorIndication, errorStatus, errorIndex, varBindTable = await bulk_cmd(
                snmpEngine,
                UsmUserData("usr-none-none"),
                await UdpTransportTarget.create((host, self.AGNT_PORT)),
                ContextData(),
                0,
                50,
                *varBinds,
            )

            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print(
                    f"{errorStatus.prettyPrint()} at {varBinds[int(errorIndex) - 1][0] if errorIndex else '?'}"
                )
            else:
                for varBind in varBindTable:
                    print(" = ".join([x.prettyPrint() for x in varBind]))

            varBinds = varBindTable
            if is_end_of_mib(varBinds):
                break
        return

    # SNMP metrics calculations
    async def get_cpu_utilization(self):
        idle = await self.get(self.OIDS["cpu_idle"])
        return 100 - idle

    async def get_memory_usage(self):
        total = await self.get(self.OIDS["mem_total"])
        avail = await self.get(self.OIDS["mem_avail"])
        used = total - avail
        return {"total_kb": total, "used_kb": used, "percent_used": used / total * 100}

    async def get_disk_usage(self):
        total = await self.get(self.OIDS["disk_total"])
        avail = await self.get(self.OIDS["disk_avail"])
        used = total - avail
        return {"total_kb": total, "used_kb": used, "percent_used": used / total * 100}

    async def get_interface_stats(self, interval=5):
        descr = await self.walk(self.OIDS["if_descr"])
        speed = await self.walk(self.OIDS["if_speed"])
        in_oct1 = await self.walk(self.OIDS["if_in_octets"])
        out_oct1 = await self.walk(self.OIDS["if_out_octets"])
        in_err1 = await self.walk(self.OIDS["if_in_errors"])
        out_err1 = await self.walk(self.OIDS["if_out_errors"])
        in_pkt1 = await self.walk(self.OIDS["if_in_packets"])
        out_pkt1 = await self.walk(self.OIDS["if_out_packets"])

        await asyncio.sleep(interval)

        in_oct2 = await self.walk(self.OIDS["if_in_octets"])
        out_oct2 = await self.walk(self.OIDS["if_out_octets"])
        in_err2 = await self.walk(self.OIDS["if_in_errors"])
        out_err2 = await self.walk(self.OIDS["if_out_errors"])
        in_pkt2 = await self.walk(self.OIDS["if_in_packets"])
        out_pkt2 = await self.walk(self.OIDS["if_out_packets"])

        stats = {}
        for idx, (_, name) in enumerate(descr):
            spd = int(speed[idx][1])
            in_oct_delta = int(in_oct2[idx][1]) - int(in_oct1[idx][1])
            out_oct_delta = int(out_oct2[idx][1]) - int(out_oct1[idx][1])
            in_err_delta = int(in_err2[idx][1]) - int(in_err1[idx][1])
            out_err_delta = int(out_err2[idx][1]) - int(out_err1[idx][1])
            in_pkt_delta = int(in_pkt2[idx][1]) - int(in_pkt1[idx][1])
            out_pkt_delta = int(out_pkt2[idx][1]) - int(out_pkt1[idx][1])

            in_bps = in_oct_delta * 8 / interval
            out_bps = out_oct_delta * 8 / interval
            util_in = in_bps / spd * 100 if spd else 0
            util_out = out_bps / spd * 100 if spd else 0
            packet_loss_in = (in_err_delta / in_pkt_delta * 100) if in_pkt_delta else None
            packet_loss_out = (out_err_delta / out_pkt_delta * 100) if out_pkt_delta else None

            stats[name] = {
                "in_bps": in_bps,
                "out_bps": out_bps,
                "utilization_in_percent": util_in,
                "utilization_out_percent": util_out,
                "in_errors_per_sec": in_err_delta / interval,
                "out_errors_per_sec": out_err_delta / interval,
                "packet_loss_in_percent": packet_loss_in,
                "packet_loss_out_percent": packet_loss_out,
            }
        return stats

    async def retrieve_mib_oids(self):
        """
        Retrieves all MIB databases and their corresponding OIDs in JSON format
        for each specified vendor: Standard, Ubiquiti, Cisco, Juniper.
        Returns a dict mapping vendor -> list of parsed MIB JSON objects.
        """
        base_search_url = "https://mibbrowser.online/mibdb_search.php"
        base_url = "https://mibbrowser.online/"
        vendors = ["tp-link"]
        standard_vendors = ['https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.41112.&vendor=Ubiquiti', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.9.&vendor=Cisco', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.2.1.&vendor=Standard', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.311.&vendor=Microsoft-Windows', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.2636.&vendor=Juniper', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.25461.&vendor=Palo%20Alto', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.14823.&vendor=Aruba', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.12356.&vendor=Fortinet-FortiGate', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.6574.&vendor=Synology', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.6876.&vendor=VMware-ESXi', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.8741.&vendor=SonicWall', 'https://mibbrowser.online/mibdb_search.php?search=1.3.6.1.4.1.11863.&vendor=TP-Link']
        results = {}
        vendor_search_params = {'allvendors': 1}

        async with httpx.AsyncClient() as client:
            """
            resp = await client.get(
                base_search_url, 
                params=vendor_search_params
            )
            html = resp.text

            soup = BeautifulSoup(html, "html.parser")
            mib_links = []
            # Find all links to individual MIB pages
            for a in soup.select("a"):
                href = a.get("href", "")
                if href.startswith("mibdb_search.php?search="):
                    #print(href)
                    if any(vendor.lower() in href.lower() for vendor in vendors):
                        #print(href)
                        mib_links.append(href.replace('\n',''))
            
            """
          
            for link in standard_vendors:
                #mib_page_url = f"{base_url}{link}"
                resp_mib = await client.get(link)
                #print(resp_mib.text)
                mib_html = resp_mib.text
                mib_soup = BeautifulSoup(mib_html, "html.parser")
                for a in mib_soup.select('a'):
                    mib_href = a.get("href", "")
                    if mib_href.startswith("mibdb_search.php?mib="):
                        json_url=f"{base_url}{mib_href.replace('\n','')}"
                        resp_json = await client.get(json_url)
                        json_html = resp_json.text
                        json_soup = BeautifulSoup(json_html,"html.parser")
                        for a in json_soup.select('a'):
                            json_href = a.get("href", "")
                            if json_href.startswith("mibs_json"):
                                print(json_href)
                                #json_dwnld = await client.get(f"{base_url}{json_href.replace('\n','')}")
                                #json_dwnld.json()

    async def discover_snmp_devices(self, subnet: list):
        self.logger.info(f"Scanning subnet {subnet} for SNMP-enabled devices...")
        devices = []
        for ip in subnet:
            try:
                response = await self.get(str(ip), self.OIDS["uptime"])
                if response:
                    self.logger.info(f"Found SNMP device: {ip}")
                    devices.append(str(ip))
            except Exception:
                continue
        return devices
    
    async def collect_remote_snmp_stats(self, ip):
        self.logger.info(f"\nSNMP Stats for {ip}")
        stats = {}
        for key, oid in self.OIDS.items():
            result = await self.get(ip, oid)
            stats[key] = result if result else "N/A"
        for k, v in stats.items():
            self.logger.info(f"{k}: {v}")
        return stats if isinstance(stats, dict) else None
    
    async def snmp_trap_listener(self):
        while True:
            snmpEngine = engine.SnmpEngine()

            config.add_transport(
                snmpEngine,
                udp.DOMAIN_NAME,
                udp.UdpTransport().open_server_mode(('0.0.0.0', 162))
            )

            config.add_v1_system(snmpEngine, 'my-area', 'public')

            async def cbFun(snmpEngine, stateReference, contextEngineId,
                            contextName, varBinds, cbCtx):
                trap = {}
                for name, val in varBinds:
                    trap[str(name)] = str(val)
                    self.trap_log.append({str(name): str(val)})
                self.logger.info("🔔 SNMP Trap received:", trap)
                
            ntfrcv.NotificationReceiver(snmpEngine, cbFun)

            await snmpEngine.transport_dispatcher.job_started(1)
            try:
                await snmpEngine.transport_dispatcher.run_dispatcher()
            except Exception as e:
                self.logger.info("Trap dispatcher error:", e)
                snmpEngine.transport_dispatcher.close_dispatcher()