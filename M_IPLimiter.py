import asyncio
import websockets
import re
import datetime
import time
import requests
import json
import yaml
import logging
import os
logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s: %(levelname)s - %(name)s: %(message)s', datefmt='%d-%b-%y %H:%M:%S')
logging.getLogger('websockets').setLevel(logging.ERROR)
logger.setLevel(os.environ.get("LOGLEVEL", "DEBUG"))


def load_config(config_file:str):
    logger.info(f"Loading Config file: {config_file}")
    try:
        with open(config_file, 'r') as conf_file:
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
        return config


class XrayLogs:
    def __init__(self, panel_url:str, login_username:str, login_password:str, limited_users:dict):
        self.url = panel_url
        self.limited_users = limited_users
        self.data = {}
        self.login_username = login_username
        self.login_password = login_password
        self.token = ""
        self.nodes = []
        self.headers = {}
        self.get_token()
        self.get_nodes()
        c_time = time.mktime(datetime.datetime.utcnow().timetuple())
        for k,v in limited_users.items():
            self.data[k] = {'status':(True, c_time), 'limit': v, 'ips': {}, 'warn': (0, 0)}

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
                req = requests.post(url, data=payload, headers=headers)
                if req.status_code == 200:
                    response = json.loads(req.text)
                    logger.debug("Security token is acquired...")
                    break
                elif req.status_code == 422:
                    logger.critical("Server authentication failed. Check username/password in Config file...")
                    raise requests.HTTPError(422)
            except Exception as e:
                logger.exception(f'e')
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

    async def get(self, node_id:int = 0):
        if node_id == 0:
            url = f"wss://{self.url}/api/core/logs?token={self.token}"
        else:
            url = f"wss://{self.url}/api/node/{node_id}/logs?token={self.token}"
        async with websockets.connect(url) as ws:
            while True:
                try:
                    logs = await ws.recv()
                except Exception as e:
                     logger.error(f"Cannot get Logs from server")
                     self.get_token()
                else:
                    for l in logs.split('\n'):
                        self.parse_logs(l)

    def parse_logs(self, xray_log):
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
                    c_date = datetime.datetime.strptime(use_time[0],"%Y/%m/%d").date()
                    c_time = datetime.datetime.strptime(use_time[1],"%H:%M:%S").time()
                    connect_time = datetime.datetime.combine(c_date,c_time).timetuple()
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
                    for k,v in user_ips.items():
                        if v == oldest_time:
                            oldest_ip = k
                    if current_time - oldest_time > 200:
                        self.data.get(email).get('ips').pop(oldest_ip)
                        self.data.get(email).get('ips')[ip_address] = connect_time
                    else:
                        #logger.debug(f"Going to warn {email}...")
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
            response = requests.get(url, headers=self.headers).text
        except requests.RequestException as e:
            logger.exception(f"Cannot retrive {url}: {e}")
            self.get_nodes()
        else:
            for node in json.loads(response):
                node_name = node.get('name')
                node_id = node.get('id')
                self.nodes.append((node_name, node_id))

    async def get_data(self):
        while True:
            logger.debug(self.data)
            await asyncio.sleep(5)

    def get_time(self, type:int = 1):
        if type == 1:
            return time.mktime(datetime.datetime.utcnow().timetuple())
        elif type == 2:
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
            req = requests.put(url, data=json.dumps(status), headers=self.headers)
            if req.status_code == 422:
                logger.debug("Security token is expired. Requesting another one...")
                self.get_token()
                logger.debug(f"Trying again to disable User {email}")
                self.disable_user(email)
                return
            elif req.status_code != 200:
                raise requests.HTTPError(f"Status Code: {req.status_code}")
        except Exception as e:
            logger.exception(f"Can't disable User {email}: {e}\nTrying again...")
            time.sleep(5)
            self.disable_user(email)
        else:
            logger.info(f"User {email} Disabled...")

    def enable_user(self, email):
        url = f"https://{self.url}/api/user/{email}"
        status = {"status": "active"}
        logger.info(f"Enabling User {email}...")
        try:
            req = requests.put(url, data=json.dumps(status), headers=self.headers)
            if req.status_code == 422:
                logger.debug("Security token is expired. Requesting another one...")
                self.get_token()
                logger.debug(f"Trying again to enable User {email}")
                self.enable_user(email)
                return
            elif req.status_code != 200:
                raise requests.HTTPError(f"Status Code: {req.status_code}")
        except Exception as e:
            logger.exception(f"Can't enable User {email}: {e}\nTrying again...")
            self.enable_user(email)
        else:
            logger.info(f"User {email} Enabled...")
            self.data.get(email)['status'] = (True, self.get_time())


async def jobs(xray_logs_obj):
    tasks = dict()
    tasks['t1'] = asyncio.create_task(xray_logs_obj.get())
    for node in xray_logs_obj.nodes:
        tasks[node[0]] = asyncio.create_task(xray_logs_obj.get(node_id=node[1]))
    #tasks['t2'] = asyncio.create_task(xray_logs_obj.get_data())
    tasks['t3'] = asyncio.create_task(xray_logs_obj.check_users())
    await asyncio.wait(list(tasks.values()))


def main():
    config = load_config('/app/config/config.yml')
    panel_url = config.get('panel').get('url')
    login_username = config.get('panel').get('username')
    login_password = config.get('panel').get('password')
    users = config.get('users')
    xray_logs_obj = XrayLogs(panel_url=panel_url, login_username=login_username, login_password=login_password,
                             limited_users=users)
    asyncio.run(jobs(xray_logs_obj))


main()
