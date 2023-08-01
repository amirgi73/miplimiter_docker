import asyncio
import copy

import websockets
import re
import datetime
import time
import requests
import json
import yaml
import logging
import hashlib
from deepdiff import DeepDiff
from argparse import ArgumentParser
from pathlib import Path

log_level = logging.ERROR
parser = ArgumentParser()
parser.add_argument("config")
parser.add_argument("-v", "--verbose", action="store_true")
args = parser.parse_args()
config_file = Path(args.config)
if args.verbose:
    log_level = logging.DEBUG
else:
    log_level = logging.INFO

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s: %(levelname)s - %(name)s: %(message)s', datefmt='%d-%b-%y %H:%M:%S')
logging.getLogger('websockets').setLevel(logging.ERROR)
logger.setLevel(log_level)


class XrayLogs:
    def __init__(self, configfile: str):
        self.config = {}
        self.config_file = configfile
        self.load_config()
        self.config_file_hash = self.get_config_hash()
        self.url = self.config.get('panel').get('url')
        self.login_username = self.config.get('panel').get('username')
        self.login_password = self.config.get('panel').get('password')
        self.data = {}
        self.token = ""
        self.nodes = []
        self.headers = {}
        self.get_token()
        self.get_nodes()
        self.create_data()

    def load_config(self):
        logger.info(f"Loading Config file: {self.config_file}")
        try:
            with open(self.config_file, 'r') as conf_file:
                config = yaml.safe_load(conf_file)
                logger.info("Config Loaded...")
        except FileNotFoundError:
            logger.critical(f"Couldn't find Config file: {conf_file}\nExiting...")
            exit(1)
        except yaml.YAMLError as e:
            logger.critical(f"Bad Config: {e}\nExiting...")
            exit(1)
        panel_url = config.get('panel').get('url')
        login_username = config.get('panel').get('username')
        login_password = config.get('panel').get('password')
        users = config.get('users')
        if not panel_url or not login_username or not login_password or not users or type(users) != dict:
            logger.critical("Wrong Config! Please check your config file...")
            exit(1)
        else:
            self.config = config

    def get_config_hash(self) -> str:
        file_to_check = self.config_file
        file_hash = hashlib.sha256()
        with open(file_to_check, 'rb') as conf_file:
            for byte_block in iter(lambda: conf_file.read(4096), b""):
                file_hash.update(byte_block)
        return file_hash.hexdigest()

    def create_data(self) -> None:
        users = self.config.get('users')
        c_time = time.mktime(datetime.datetime.utcnow().timetuple())
        for k, v in users.items():
            self.data[k] = {'status': (True, c_time), 'limit': v, 'ips': {}, 'warn': (0, 0)}

    def is_config_updated(self) -> bool:
        if self.get_config_hash() == self.config_file_hash:
            return False
        else:
            return True

    async def check_config_for_update(self):
        while True:
            if self.is_config_updated():
                logger.info("Config is updated... Reloading...")
                self.load_config()  # Loading the config again...
                self.create_data()  # Creating data dict based of new config...
                self.config_file_hash = self.get_config_hash()  # Saving the current hash
            await asyncio.sleep(600)  # Waiting for 10m and then checking again

    def get_token(self):
        url = f"https://{self.url}/api/admin/token"
        logger.debug(f"Requesting security token from server ({url})...")
        headers = {
            "accept": "application / json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = {
            "username": self.login_username,
            "password": self.login_password
        }
        for c in range(5):
            try:
                req = requests.post(url, data=payload, headers=headers, timeout=3)
                if req.status_code == 200:
                    response = json.loads(req.text)
                    logger.debug("Security token is acquired...")
                    break
                elif req.status_code == 422:
                    logger.critical("Server authentication failed. Check username/password in Config file...")
                    raise requests.HTTPError(422)
            except Exception as e:
                logger.exception(e)
                if str(e) == '422':
                    exit(3)
                else:
                    logger.error(f"Cannot get token from {url}: {e}\nRetrying in 5s...")
                    time.sleep(5)
        else:
            logger.critical(f"Couldn't get token from server ({url})\n Exiting...")
            exit(2)
        self.token = response.get("access_token")
        token_type = response.get("token_type").capitalize()
        self.headers = {
            "accept": "application / json",
            "Authorization": f"{token_type} {self.token}",
            "Content-Type": "application/json"
        }

    async def get(self, node_id: int = 0):
        if node_id == 0:
            url = f"wss://{self.url}/api/core/logs?token={self.token}"
        else:
            url = f"wss://{self.url}/api/node/{node_id}/logs?token={self.token}"
        async for ws in websockets.connect(url):
            try:
                logs = await ws.recv()
            except websockets.ConnectionClosed:
                logger.error(f"Connection Closed...")
                await asyncio.sleep(0)
            except websockets.InvalidStatusCode as e:
                logger.critical(e)
                self.get_token()
                await asyncio.sleep(1)
            except Exception as e:
                logger.exception(e)
                await asyncio.sleep(0)
            else:
                for line in logs.split('\n'):
                    self.parse_logs(line)

    def parse_logs(self, xray_log):
        email = None
        acceptance_match = re.search(r"\baccepted\b", xray_log)
        if not acceptance_match:
            return
        else:
            ip_address = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", xray_log).group(1)
        if ip_address:
            email = re.search(r"email:\s*([A-Za-z0-9._%+-]+)", xray_log).group(1)
        if email:
            email = re.search(r"\.(.*)", email).group(1)
            if email in self.data:
                if self.data.get(email).get('status') is False:
                    return
                use_time = xray_log.split(" ")
                if "BLOCK]" in use_time:
                    return
                else:
                    c_date = datetime.datetime.strptime(use_time[0], "%Y/%m/%d").date()
                    c_time = datetime.datetime.strptime(use_time[1], "%H:%M:%S").time()
                    connect_time = datetime.datetime.combine(c_date, c_time).timetuple()
                    connect_time = time.mktime(connect_time)
                user_data = self.data.get(email)     # dict
                user_ips = user_data.get('ips')     # dict
                user_limit = user_data.get('limit')     # int
                if ip_address in user_ips:
                    self.data[email]['ips'][ip_address] = connect_time
                elif len(user_ips) < user_limit:
                    self.data[email]['ips'][ip_address] = connect_time
                elif len(user_ips) >= user_limit:
                    current_time = time.mktime(datetime.datetime.utcnow().timetuple())
                    oldest_time = sorted(list(user_ips.values()))[0]
                    oldest_ip = ''
                    for k, v in user_ips.items():
                        if v == oldest_time:
                            oldest_ip = k
                    if current_time - oldest_time > 200:
                        self.data.get(email).get('ips').pop(oldest_ip)
                        self.data.get(email).get('ips')[ip_address] = connect_time
                    else:
                        # logger.debug(f"Going to warn {email}...")
                        user_warn = self.data.get(email)['warn']
                        warns = user_warn[0]
                        last_warn_time = user_warn[1]
                        if current_time - last_warn_time >= 300:
                            self.data.get(email)['warn'] = (0, current_time)
                            logger.info(f"{email}: Warn level reseted to 0...")
                        elif 300 > current_time - last_warn_time > 100:
                            self.data.get(email)['warn'] = (warns+1, current_time)
                            logger.info(f"User {email} Warned. Total Warns: {self.data.get(email).get('warn')[0]}")

    def get_nodes(self):
        url = f"https://{self.url}/api/nodes"
        try:
            response = requests.get(url, headers=self.headers, timeout=3)
        except requests.RequestException as e:
            logger.exception(f"Cannot retrieve {url}: {e}")
            return self.get_nodes()
        else:
            if response.status_code == 422:
                self.get_token()
                return self.get_nodes()
            for node in json.loads(response.text):
                node_name = node.get('name')
                node_id = node.get('id')
                self.nodes.append((node_name, node_id))

    async def get_data(self):
        last_printed_data = {}
        while True:
            diff = DeepDiff(last_printed_data, self.data)
            if diff != {}:
                logger.debug("\033[96m" + f"Data changed:\n{diff.pretty()}")
                last_printed_data = copy.deepcopy(self.data)
            await asyncio.sleep(30)

    def get_time(self, t_type: int = 1):
        if t_type == 1:
            return time.mktime(datetime.datetime.utcnow().timetuple())
        elif t_type == 2:
            return datetime.datetime.utcnow()
        else:
            return datetime.datetime.utcnow()

    async def check_users(self):
        while True:
            for user in self.data.keys():
                if self.data.get(user).get('warn')[0] >= 3:
                    current_time = self.get_time()
                    self.disable_user(user)
                    self.data.get(user)['status'] = (False, current_time)
                    self.data.get(user)['warn'] = (0, current_time)
                    await asyncio.sleep(300)
                    self.enable_user(user)
                    self.data.get(user)['status'] = (True, current_time)
                elif 0 < self.data.get(user).get('warn')[0] < 3:
                    current_time = self.get_time()
                    if current_time - self.data.get(user).get('warn')[1] > 300:
                        self.data.get(user)['warn'] = (0, 0)
            await asyncio.sleep(30)

    def disable_user(self, email):
        url = f"https://{self.url}/api/user/{email}"
        status = {"status": "disabled"}
        logger.info(f"Disabling User {email}...")
        try:
            req = requests.put(url, data=json.dumps(status), headers=self.headers, timeout=3)
            if req.status_code == 422:
                logger.debug("Security token is expired. Requesting another one...")
                self.get_token()
                logger.debug(f"Trying again to disable User {email}")
                return self.disable_user(email)
            elif req.status_code != 200:
                raise requests.HTTPError(f"Status Code: {req.status_code}")
        except Exception as e:
            logger.exception(f"Can't disable User {email}: {e}\nTrying again...")
            time.sleep(5)
            return self.disable_user(email)
        else:
            logger.info(f"User {email} Disabled...")

    def enable_user(self, email):
        url = f"https://{self.url}/api/user/{email}"
        status = {"status": "active"}
        logger.info(f"Enabling User {email}...")
        try:
            req = requests.put(url, data=json.dumps(status), headers=self.headers, timeout=3)
            if req.status_code == 422:
                logger.debug("Security token is expired. Requesting another one...")
                self.get_token()
                logger.debug(f"Trying again to enable User {email}")
                return self.enable_user(email)
            elif req.status_code != 200:
                raise requests.HTTPError(f"Status Code: {req.status_code}")
        except Exception as e:
            logger.exception(f"Can't enable User {email}: {e}\nTrying again...")
            return self.enable_user(email)
        else:
            logger.info(f"User {email} Enabled...")
            self.data.get(email)['status'] = (True, self.get_time())


async def jobs(xray_logs_obj, loglevel):
    tasks = dict()
    tasks['t1'] = asyncio.create_task(xray_logs_obj.get(node_id=0))
    for node in xray_logs_obj.nodes:
        tasks[node[0]] = asyncio.create_task(xray_logs_obj.get(node_id=node[1]))
    if loglevel is logging.DEBUG:
        tasks['t2'] = asyncio.create_task(xray_logs_obj.get_data())
    tasks['t3'] = asyncio.create_task(xray_logs_obj.check_users())
    tasks['t4'] = asyncio.create_task(xray_logs_obj.check_config_for_update())
    await asyncio.wait(list(tasks.values()))


def main(conf_file):
    xray_logs_obj = XrayLogs(configfile=conf_file)
    asyncio.run(jobs(xray_logs_obj, log_level))


main(config_file)
