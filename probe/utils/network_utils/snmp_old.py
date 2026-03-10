from pysnmp.hlapi.v3arch import *
from scapy.all import *
from scapy.all import *
from scapy import *
from scapy.tools import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import pyshark
from utils.network_utils.base.Network import Network
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c
from time import time
from pysnmp.hlapi.asyncio import *
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from collections import deque

class NetworkSNMP(Network):
    def __init__(self):
        super().__init__()

        # SNMP community string and version
        self.SNMP_COMMUNITY = 'public'
        self.SNMP_PORT = 162
        self.SNMP_TRAP_HOST = 'monitor.baughcl.com'
        self.TIMEOUT = 1
        self.RETRIES = 1

        # Common SNMP OIDs
        self.SNMP_OIDS = {
            "uptime": '1.3.6.1.2.1.1.3.0',
            "cpu": '1.3.6.1.4.1.2021.11.10.0',  # UCD-SNMP CPU idle
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
        }
        self.trap_log = deque(maxlen=100)  # Store recent traps in memory

    def snmp_get(self, ip, oid):
        errorIndication, errorStatus, errorIndex, varBinds = next(
            get_cmd(SnmpEngine(),
                CommunityData(self.SNMP_COMMUNITY, mpModel=0),
                UdpTransportTarget((ip, self.SNMP_PORT), timeout=self.TIMEOUT, retries=self.RETRIES),
                ContextData(),
                ObjectType(ObjectIdentity(oid)))
        )
        if errorIndication or errorStatus:
            return None
        for varBind in varBinds:
            return varBind[1]

    def discover_snmp_devices(self, subnet: list):
        self.logger.info(f"Scanning subnet {subnet} for SNMP-enabled devices...")
        devices = []
        for ip in subnet:
            try:
                response = self.snmp_get(str(ip), self.SNMP_OIDS["uptime"])
                if response:
                    self.logger.info(f"Found SNMP device: {ip}")
                    devices.append(str(ip))
            except Exception:
                continue
        return devices

    def collect_remote_snmp_stats(self, ip):
        self.logger.info(f"\nSNMP Stats for {ip}")
        stats = {}
        for key, oid in self.SNMP_OIDS.items():
            result = self.snmp_get(ip, oid)
            stats[key] = result if result else "N/A"
        for k, v in stats.items():
            self.logger.info(f"{k}: {v}")
        return stats if isinstance(stats, dict) else None

    def send_snmp_trap(self, community='public'):
        self.logger.info(f"\n📤 Sending SNMP trap to {self.SNMP_TRAP_HOST}:{self.SNMP_PORT}...")
        snmpEngine = engine.SnmpEngine()

        config.add_v1_system(snmpEngine, 'my-area', community)

        config.add_target_parameters(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 1)
        config.add_target_address(
            snmpEngine,
            'my-nms',
            udp.DOMAIN_NAME,
            (self.SNMP_TRAP_HOST, self.SNMP_PORT),
            'my-creds'
        )

        notification_type = v2c.apiTrapPDU.get_response()
        v2c.apiTrapPDU.set_defaults(notification_type)
        v2c.apiTrapPDU.set_varbinds(notification_type, [
            (ObjectIdentifier('1.3.6.1.2.1.1.3.0'), TimeTicks(int(time() * 100))),
            (ObjectIdentifier('1.3.6.1.2.1.1.5.0'), OctetString('Python SNMP Monitor')),
            (ObjectIdentifier('1.3.6.1.4.1.8072.2.3.0.1'), OctetString('Custom event occurred')),
        ])

        send_notification(
            snmpEngine,
            'my-creds',
            'my-nms',
            None,
            'trap',
            notification_type
        )

        snmpEngine.transport_dispatcher.run_dispatcher()

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


