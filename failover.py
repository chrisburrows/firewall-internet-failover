#!/usr/bin/python3

import json
import subprocess
import time
import logging
import os
import re
import uuid
import sys
import platform
from queue import Queue
from threading import Thread
import paho.mqtt.client as mqtt

PROXY_ARP_CONFIG_PATH = "/proc/sys/net/ipv4/conf/{ifname}/proxy_arp"

HOSTNAME = platform.node()
MAC_ADDRESS = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

MQTT_BROKER = os.getenv("MQTT_BROKER", "mqtt.local")
MQTT_USER = os.getenv("MQTT_USER", "firewall")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "password")
UPDATE_INTERVAL = 30

# MQTT topic paths
MQTT_BASE_TOPIC = f"firewall/{HOSTNAME}/interface"
MQTT_STATUS_TOPIC = MQTT_BASE_TOPIC + "/status"
MQTT_ACTIVE_INTERFACE_TOPIC = MQTT_BASE_TOPIC + "/active"


def get_pi_info():
    '''Extract board revision from cpuinfo file'''

    info = dict()
    try:
        f = open('/proc/cpuinfo','r')
        for line in f:
          if line.startswith('Revision'):
            info['revision'] = line.split(":")[1].strip()

          if line.startswith('Serial'):
            info['serial'] = line.split(":")[1].strip()

          if line.startswith('Model'):
            info['model'] = line.split(":")[1].strip()
        f.close()
    except Exception as e:
        logger.error(str(e))
 
    return info


def setup_mqtt():
    '''Initialise MQTT client'''

    client = mqtt.Client(client_id="if-failover-" + platform.node())
    client.loop_start()
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.max_queued_messages_set(10)
    client.will_set(MQTT_STATUS_TOPIC, payload="offline")
    client.connect(MQTT_BROKER, 1883, keepalive=UPDATE_INTERVAL * 3)
    return client


def on_connect(client: mqtt.Client, userdata: object, flags: int, rc: int):
    """The callback for when the client receives a CONNACK response from the server."""

    logger.info("MQTT: Connected to broker with result code " + str(rc))

    if rc == mqtt.CONNACK_ACCEPTED:
        client.publish(MQTT_BASE_TOPIC + "/status", payload="online", retain=True)

        # update discovery each time we connect
        publish_ha_discovery(client)


def on_disconnect(client: mqtt.Client, userdata: object, flags: int, rc: int, properties):
    '''The callback for a disconnect from MQTT broker'''
    logger.warning(f"Disconnected from MQTT broker: {rc}")


def publish_ha_discovery(client: mqtt.Client):
    """Publish discovery for the monitor and active interface"""
    logger.info("MQTT: Publishing Home Assistant discovery data")
    payload = {
        "device": {
            "ids": f"{MAC_ADDRESS}",
            "name": "Firewall Internet Interface",
            "mf": "Belstead",
            "mdl": "Raspberry Pi",
            "sw": "1.0",
            "sn": f"{pi_info['serial']}",
            "hw": f"{pi_info['model']}"
        },
        "origin": {
            "name": "failover.py",
            "sw": "1.0",
            "url": "http://github.com/chrisburrows"
        },
        "components": {
            "primary_name": {
                "name": "Primary Interface Name",
                "platform": "sensor",
                "value_template": "{{ value_json.primary.name }}",
                "unique_id": f"{HOSTNAME}_primary_ifname",
                "icon": "mdi:wan"
            },
            "primary_state": {
                "name": "Primary Interface State",
                "platform": "binary_sensor",
                "device_class": "connectivity",
                "value_template": "{{ value_json.primary.state }}",
                "unique_id": f"{HOSTNAME}_primary_state"
                #"icon": "mdi:wan"
            },
            "secondary_name": {
                "name": "Secondary Interface Name",
                "platform": "sensor",
                "value_template": "{{ value_json.secondary.name }}",
                "unique_id": f"{HOSTNAME}_secondary_ifname",
                "icon": "mdi:wan"
            },
            "secondary_state": {
                "name": "Secondary Interface State",
                "platform": "binary_sensor",
                "device_class": "connectivity",
                "value_template": "{{ value_json.secondary.state }}",
                "unique_id": f"{HOSTNAME}_secondary_state"
                #"icon": "mdi:wan"
            },
            "active_interface": {
                "name": "Active Interface",
                "platform": "sensor",
                "value_template": "{{ value_json.active }}",
                "unique_id": "{HOSTNAME}_active_iface",
                "icon": "mdi:directions-fork"
            }
        },
        "state_topic": MQTT_BASE_TOPIC,
        "availability_topic": MQTT_STATUS_TOPIC
    }
    discovery_topic = f"homeassistant/device/firewall-interface-failover/{HOSTNAME}/config"
    client.publish(discovery_topic, payload=json.dumps(payload), retain=True)


def monitor_interface(test_ip: str, verify_ip: str, iface: str, up_threshold: int, down_threshold: int, interval: int, ifs: dict, queue: Queue) -> None:
    '''Loop forever a track up / down status of an interface'''

    logger.info(f"Monitor interface: {iface} at {interval} second intervals with up threshold {up_threshold} and down threshold {down_threshold}")

    while True:

        ifs[iface] = ping(test_ip, iface)
        queue.put(iface)
        count = 0
        threshold = down_threshold if ifs[iface] else up_threshold

        while count < threshold:
            success = ping(test_ip, iface)
            if success != ifs[iface]:
                count = count + 1
            else:
                count = 0
            logger.debug(f"Count {count}")
            time.sleep(interval)

        # verify against a different endpoint
        logger.info(f"Verifying interface {iface} status")
        if ping(verify_ip, iface) != ifs[iface]:
            ifs[iface] = not ifs[iface]
            queue.put(iface)


def update_interface_status(client: mqtt.Client, cfg: dict, ifs: dict, queue: Queue) -> None:
    '''Update status for an interface'''

    while True:
        try:
            iface = queue.get()
            logger.debug(f"Processing state change on {iface}")

            p_state = ifs[cfg['primary']['interface']]
            s_state = ifs[cfg['secondary']['interface']]

            preferred = 'primary'
            if not p_state and s_state:
                preferred = 'secondary'

            preferred_interface = cfg[preferred]['interface']
            default_interface = get_interface("8.8.8.8")
            default_is_primary = cfg['primary']['interface'] == default_interface

            logger.debug(f"Preferred interface {preferred} ({cfg[preferred]['interface']}), current interface {default_interface}")

            if preferred_interface != default_interface:
                # need to change default route

                if preferred == 'primary':
                    replace_route(cfg['primary']['next_hop'], cfg['metric']['primary'])
                    replace_route(cfg['secondary']['next_hop'], cfg['metric']['secondary'])

                else:
                    replace_route(cfg['secondary']['next_hop'], cfg['metric']['primary'])
                    replace_route(cfg['primary']['next_hop'], cfg['metric']['secondary'])

            logger.debug(f"Default interface {default_interface}")

            payload = {
                "primary": {
                    "name": f"{cfg['primary']['interface']}",
                    "state": f"{up_down(ifs[cfg['primary']['interface']])}"
                },
                "secondary": {
                    "name": f"{cfg['secondary']['interface']}",
                    "state": f"{up_down(ifs[cfg['secondary']['interface']])}"
                },
                "active": "primary" if default_is_primary else "secondary"
            }
            while not client.is_connected():
                time.sleep(0.5)
            client.publish(MQTT_BASE_TOPIC, payload=json.dumps(payload), retain=True)


        except Exception as e:
            logger.error(str(e))


def up_down(state) -> str:
    return "ON" if state else "OFF"


def load_config(path: str) -> object:
    '''Load configuration file'''
    with open(path) as stream:
        return json.load(stream)


def get_interface(next_hop: str) -> str:
    '''Get the local interface used to reach a destination'''

    result = subprocess.run(f"ip route get {next_hop}", capture_output=True, shell=True)
    return result.stdout.decode("utf-8").split()[4] if result.returncode == 0 else None


def replace_route(next_hop: str, metric: int):
    '''Replace default route'''

    logger.debug(f"Replacing route: {next_hop} metric {metric}")
    result = subprocess.run(f"ip route delete 0.0.0.0/0 via {next_hop}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    result = subprocess.run(f"ip route add 0.0.0.0/0 via {next_hop} metric {metric}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)

    return result.returncode == 0


def enable_proxy_arp(ifname: str) -> None:
    '''Enable proxy arp for an interface'''
 
    logger.info(f"Enabling proxy arp for {ifname}")
    with open(PROXY_ARP_CONFIG_PATH.format(ifname=ifname), 'w') as file:
        file.write('1')


def ping(ip: str, iface: str) -> bool:
    '''Ping the test endpoint via selected interface'''

    result = subprocess.run(f"ping -W 1 -c 1 -I {iface} {ip}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    
    ok = result.returncode == 0
    logger.debug(f"Pinging {ip} via {iface} {'up' if ok else 'down'}")
    return ok


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('{asctime} - {funcName:28} - {levelname:8} {message}', style='{')
handler.setFormatter(formatter)

logger.addHandler(handler)

#logging.basicConfig(filename='/var/log/failover.log', level=logging.INFO)
cfg = load_config("/usr/local/etc/failover.yml")

pi_info = get_pi_info()
interface_status = dict()

logger.info("Starting...")

queue = Queue()

while True:
    client = setup_mqtt()

    for iface in ['primary', 'secondary']:
        if cfg[iface]['proxy_arp']:
            enable_proxy_arp(cfg[iface]['interface'])

    primary = Thread(target=monitor_interface, 
                     args=[cfg['ping']['test_ip'], cfg['ping']['verify_ip'], 
                           cfg['primary']['interface'], 
                           cfg['ping']['success_count'], cfg['ping']['failure_count'], 
                           cfg['ping']['interval'],
                           interface_status,
                           queue ])

    secondary = Thread(target=monitor_interface, 
                       args=[cfg['ping']['test_ip'], cfg['ping']['verify_ip'], 
                             cfg['secondary']['interface'], 
                             cfg['ping']['success_count'], cfg['ping']['failure_count'], 
                             cfg['ping']['interval'],
                             interface_status,
                             queue ])
    mqtt_update = Thread(target=update_interface_status,
                         args=[client, cfg, interface_status, queue])

    primary.start()
    secondary.start()
    mqtt_update.start()

    while not client.is_connected():
        time.sleep(0.5)

    client.loop_forever(retry_first_connection=False)
