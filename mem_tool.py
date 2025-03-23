import psutil
from flask import Flask, request, jsonify
import threading
import time
import requests
import os
import pymem
import logging
import configparser
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

config = configparser.ConfigParser()
config.read('config.ini')

SERVER_ID = config['Configuration']['SERVER_ID']
MEM_TOOL_ID = config['Configuration']['MEM_TOOL_ID']
SERVER_IP = config['Configuration']['SERVER_IP']
MEM_TOOL_PORT = int(config['Configuration']['MEM_TOOL_PORT'])
VERSION = config['Configuration']['VERSION']
AUTH_SERVICE_URL = config['Configuration']['AUTH_SERVICE_URL']

current_token = None
memory_config_received = False  # 新增标志，用于标记是否已从服务器接收到内存配置

# Chinese message mapping
messages_zh = {
    "Heartbeat successful, token updated": "心跳成功，令牌已更新",
    "Heartbeat failed": "心跳失败",
    "Connection error": "连接错误",
    "Failed to read memory at": "读取内存失败，地址：",
    "Failed to write memory at": "写入内存失败，地址：",
    "Value updated successfully": "数值更新成功",
    "Unauthorized": "未授权",
    "Missing required parameters": "缺少必要参数",
    "Invalid team number": "队伍号码无效",
    "No SquadGameServer.exe process found in current directory": "在当前目录下未找到 SquadGameServer.exe 进程",
    "Multiple SquadGameServer.exe processes found": "找到多个 SquadGameServer.exe 进程",
    "Selected SquadGameServer.exe process": "已选择 SquadGameServer.exe 进程",
    "Base address": "基址",
    "Error accessing process": "访问进程时出错",
    "Updated initial_offset to": "初始偏移已更新为",
    "Updated offsets for team": "队伍偏移已更新",
    "Error updating memory config": "更新内存配置错误",
    "Memory configuration updated successfully": "内存配置更新成功",
    "Failed to update memory configuration": "内存配置更新失败",
    "initial_addr": "初始地址",
    "Invalid value provided": "提供的值无效",
    "Value must be positive": "值必须为正数",
    "Missing team parameter": "缺少队伍参数",
    "Array must contain at least two elements": "数组必须至少包含两个元素",
    "No solution found": "未找到解决方案",
    "Error in set_ticket": "设置票数时出错",
    "Error in get_ticket": "获取票数时出错",
    "Failed to initialize connection to game process": "初始化游戏进程连接失败",
    "Current directory": "当前目录",
    "Found SquadGameServer.exe process": "发现 SquadGameServer.exe 进程",
    "Matched SquadGameServer.exe process": "匹配 SquadGameServer.exe 进程",
    "Could not find SquadGameServer.exe module": "无法找到 SquadGameServer.exe 模块",
    "Value must be positive integer": "值必须为正整数",
    "Team must be 1 or 2": "队伍必须为 1 或 2",
    "Memory configuration not received yet": "尚未接收到内存配置",
    "Waiting for memory configuration from server": "正在等待从服务器获取内存配置",
}


class MemoryReader:
    def __init__(self):
        self.pm = None
        self.base_address = None
        
        self.initial_offset = None
        self.team_offsets = {
            1: None,
            2: None
        }
        self.selected_pid = None
        self.current_dir = os.path.normpath(os.getcwd()).lower()
        logging.info(f"{messages_zh['Current directory']}: {self.current_dir}")

    def update_memory_config(self, memory_config):
        try:
            logging.info("开始更新内存配置...")  # Start update memory config
            if "initial_offset" in memory_config:
                offset_str = memory_config["initial_offset"]
                if isinstance(offset_str, str) and offset_str.startswith("0x"):
                    self.initial_offset = int(offset_str, 16)
                else:
                    self.initial_offset = int(offset_str)
                logging.info(f"{messages_zh['Updated initial_offset to']}: 0x{self.initial_offset:x}")

            if "team_offsets" in memory_config:
                for team, offsets in memory_config["team_offsets"].items():
                    team_num = int(team)
                    parsed_offsets = []
                    for offset in offsets:
                        if isinstance(offset, str) and offset.startswith("0x"):
                            parsed_offsets.append(int(offset, 16))
                        else:
                            parsed_offsets.append(int(offset))
                    self.team_offsets[team_num] = parsed_offsets
                    logging.info(f"{messages_zh['Updated offsets for team']} {team_num}: {[hex(o) for o in parsed_offsets]}")
            logging.info("内存配置更新完成。")  # Memory config updated complete
            global memory_config_received
            memory_config_received = True
            return True
        except Exception as e:
            logging.error(f"{messages_zh['Error updating memory config']}: {str(e)}")
            return False

    def list_squad_processes(self):
        squad_processes = []
        logging.debug("开始查找 SquadGameServer.exe 进程...") # Start list squad process
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['name'] == 'SquadGameServer.exe':
                    proc_path = os.path.normpath(proc.info['exe']).lower()
                    proc_dir = os.path.dirname(proc_path)
                    logging.debug(f"{messages_zh['Found SquadGameServer.exe process']}: PID {proc.info['pid']}, Path {proc_path}")
                    if proc_dir == self.current_dir:
                        squad_processes.append({'pid': proc.info['pid'], 'directory': proc_dir})
                        logging.info(f"{messages_zh['Matched SquadGameServer.exe process']}: PID {proc.info['pid']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                logging.error(f"{messages_zh['Error accessing process']}: {str(e)}")
                continue
        if not squad_processes:
            logging.info("未找到匹配的 SquadGameServer.exe 进程。") # No matched squad process found
        else:
            logging.info(f"共找到 {len(squad_processes)} 个 SquadGameServer.exe 进程。") # Found count squad process
        return squad_processes

    def select_process(self):
        logging.info("开始选择进程...") # Start select process
        processes = self.list_squad_processes()
        if not processes:
            error_msg = messages_zh["No SquadGameServer.exe process found in current directory"]
            logging.error(f"{error_msg}: {self.current_dir}")
            raise Exception(error_msg)
        if len(processes) > 1:
            logging.warning(f"{messages_zh['Multiple SquadGameServer.exe processes found']}: {len(processes)}，选择第一个。") # Multiple squad process found, select first one
            self.selected_pid = processes[0]['pid']
        else:
            self.selected_pid = processes[0]['pid']
        logging.info(f"{messages_zh['Selected SquadGameServer.exe process']}: PID {self.selected_pid}")
        return True

    def check_config_received(self):
        if not memory_config_received or self.initial_offset is None or not all(self.team_offsets.values()):
            logging.error(messages_zh["Memory configuration not received yet"])
            raise Exception(messages_zh["Waiting for memory configuration from server"])
        return True

    def get_offsets(self, team):
        self.check_config_received()
        
        if team not in [1, 2]:
            raise ValueError(messages_zh["Team must be 1 or 2"])
        if not self.team_offsets[team]:
            raise Exception(messages_zh["Memory configuration not received yet"])
        return self.team_offsets[team]

    def connect(self):
        logging.info("尝试连接到游戏进程...") # Trying to connect game process
        try:
            if not self.selected_pid:
                if not self.select_process():
                    return False
            self.pm = pymem.Pymem()
            self.pm.open_process_from_id(self.selected_pid)
            module = pymem.process.module_from_name(self.pm.process_handle, "SquadGameServer.exe")
            if not module:
                raise Exception(messages_zh["Could not find SquadGameServer.exe module"])
            self.base_address = module.lpBaseOfDll
            logging.info("{}: 0x{:x}".format(messages_zh['Base address'], self.base_address))
            logging.info("连接游戏进程成功。") # Connect game process success
            return True
        except Exception as e:
            logging.error(f"{messages_zh['Connection error']}: {str(e)}")
            logging.error("连接游戏进程失败。") # Connect game process failed
            self.selected_pid = None
            return False

    def follow_pointers(self, initial_addr, offsets):
        addr = initial_addr
        for i, offset in enumerate(offsets):
            try:
                ptr = self.pm.read_ulonglong(addr)
                addr = ptr + offset
                logging.debug(f"指针层级 {i+1}, 地址: 0x{addr:x}, 偏移: 0x{offset:x}") # Pointer level info
            except pymem.exception.MemoryReadError:
                error_msg = f"{messages_zh['Failed to read memory at']} 0x{addr:x} (offset level {i + 1})"
                logging.error(error_msg)
                raise Exception(error_msg)
        return addr

    def get_ticket_value(self, team):
        logging.info(f"尝试获取队伍 {team} 的票数...") # Trying to get team ticket value
        
        # 确保已从服务器接收到配置
        self.check_config_received()
        
        if not self.pm:
            if not self.connect():
                raise Exception("Failed to connect to process") # Already logged in connect()
        try:
            offsets = self.get_offsets(team)
        except ValueError as e:
            raise Exception(str(e)) # Message from get_offsets is already Chinese
        initial_addr = self.base_address + self.initial_offset
        logging.info("{}: 0x{:x}".format(messages_zh['initial_addr'], initial_addr))
        target_addr = self.follow_pointers(initial_addr, offsets)
        try:
            value = self.pm.read_ulonglong(target_addr)
            logging.info(f"队伍 {team} 的票数为: {value}") # Team ticket value is
            return value
        except pymem.exception.MemoryReadError:
            error_msg = f"{messages_zh['Failed to read memory at']} 0x{target_addr:x}"
            logging.error(error_msg)
            raise Exception(error_msg)

    def set_ticket_value(self, team, new_value):
        logging.info(f"尝试设置队伍 {team} 的票数为: {new_value}...") # Trying to set team ticket value
        
        # 确保已从服务器接收到配置
        self.check_config_received()
        
        if not self.pm:
            if not self.connect():
                raise Exception("Failed to connect to process") # Already logged in connect()
        try:
            offsets = self.get_offsets(team)
        except ValueError as e:
            raise Exception(str(e)) # Message from get_offsets is already Chinese
        try:
            new_value = int(new_value)
            if new_value < 0:
                raise ValueError(messages_zh["Value must be positive"])
        except ValueError:
            raise Exception(messages_zh["Invalid value provided"])
        initial_addr = self.base_address + self.initial_offset
        logging.info("{}: 0x{:x}".format(messages_zh['initial_addr'], initial_addr))
        target_addr = self.follow_pointers(initial_addr, offsets)
        try:
            self.pm.write_ulonglong(target_addr, new_value)
            logging.info(f"队伍 {team} 的票数已设置为: {new_value}") # Team ticket value set to
            return True
        except pymem.exception.MemoryWriteError:
            error_msg = f"{messages_zh['Failed to write memory at']} 0x{target_addr:x}"
            logging.error(error_msg)
            raise Exception(error_msg)


memory_reader = MemoryReader()


def send_heartbeat():
    global current_token
    while True:
        payload = {
            "server_id": SERVER_ID,
            "mem_tool_id": MEM_TOOL_ID,
            "server_ip": SERVER_IP,
            "mem_tool_port": MEM_TOOL_PORT,
            "version": VERSION
        }
        logging.debug("发送心跳包...") # Sending heartbeat package
        try:
            response = requests.post(AUTH_SERVICE_URL, json=payload, verify=False, timeout=5)
            if response.status_code == 200:
                response_data = response.json()
                current_token = response_data["token"]
                logging.info(messages_zh["Heartbeat successful, token updated"])

                # 处理内存配置信息
                if "memory_config" in response_data:
                    logging.info("接收到内存配置信息，开始更新...") # Received memory config info, start update
                    if memory_reader.update_memory_config(response_data["memory_config"]):
                        logging.info(messages_zh["Memory configuration updated successfully"])
                    else:
                        logging.error(messages_zh["Failed to update memory configuration"])
            else:
                logging.warning(f"心跳响应状态码: {response.status_code}") # Heartbeat response status code
        except requests.RequestException as e:
            logging.error(f"{messages_zh['Heartbeat failed']}: {e}")
        time.sleep(60)



@app.route('/mem_tool/set/ticket', methods=['GET'])
def set_ticket():
    logging.info("Endpoint '/mem_tool/set/ticket' 被访问") # Endpoint set ticket accessed
    token = request.headers.get('X-Auth-Token')
    if token != current_token or current_token is None:
        logging.warning("未授权访问尝试") # Unauthorized access attempt
        return jsonify({'status': 'error', 'message': messages_zh['Unauthorized']}), 403
    try:
        if not memory_config_received:
            return jsonify({'status': 'error', 'message': messages_zh['Memory configuration not received yet']}), 503
            
        team = request.args.get('team')
        value = request.args.get('value')
        logging.info(f"请求参数：队伍={team}, 数值={value}") # Request params: team, value
        if not team or not value:
            logging.warning(messages_zh['Missing required parameters'])
            return jsonify({'status': 'error', 'message': messages_zh['Missing required parameters']}), 400
        team = int(team)
        if team not in [1, 2]:
            logging.warning(messages_zh['Invalid team number'])
            return jsonify({'status': 'error', 'message': messages_zh['Invalid team number']}), 400
        memory_reader.set_ticket_value(team, value)
        current_value = memory_reader.get_ticket_value(team)
        logging.info(f"票数已设置，当前队伍 {team} 票数为: {current_value}") # Ticket set, current team ticket value
        return jsonify({
            'status': 'success',
            'message': messages_zh['Value updated successfully'],
            'team': team,
            'value': current_value
        })
    except Exception as e:
        logging.error(f"{messages_zh['Error in set_ticket']}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/mem_tool/get/ticket', methods=['GET'])
def get_ticket():
    logging.info("Endpoint '/mem_tool/get/ticket' 被访问") # Endpoint get ticket accessed
    token = request.headers.get('X-Auth-Token')
    if token != current_token or current_token is None:
        logging.warning("未授权访问尝试") # Unauthorized access attempt
        return jsonify({'status': 'error', 'message': messages_zh['Unauthorized']}), 403
    try:
        if not memory_config_received:
            return jsonify({'status': 'error', 'message': messages_zh['Memory configuration not received yet']}), 503
            
        team = request.args.get('team')
        logging.info(f"请求参数：队伍={team}") # Request param: team
        if not team:
            logging.warning(messages_zh['Missing team parameter'])
            return jsonify({'status': 'error', 'message': messages_zh['Missing team parameter']}), 400
        team = int(team)
        if team not in [1, 2]:
            logging.warning(messages_zh['Invalid team number'])
            return jsonify({'status': 'error', 'message': messages_zh['Invalid team number']}), 400
        value = memory_reader.get_ticket_value(team)
        logging.info(f"获取到队伍 {team} 的票数为: {value}") # Got team ticket value
        return jsonify({'status': 'success', 'team': team, 'value': value})
    except Exception as e:
        logging.error(f"{messages_zh['Error in get_ticket']}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


if __name__ == '__main__':

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S') # Added timestamp to log

    logging.info("Squad ICU Mem Tool 服务启动...") # Mem Tool service starting
    if not memory_reader.connect():
        logging.error(messages_zh["Failed to initialize connection to game process"])
    else:
        logging.info("成功初始化与游戏进程的连接。") # Success init connection to game process

    threading.Thread(target=send_heartbeat, daemon=True).start()
    logging.info("心跳线程已启动。") # Heartbeat thread started
    logging.info("等待从服务器接收内存配置...") # Waiting for memory config from server

    app.run(host='0.0.0.0', port=MEM_TOOL_PORT)
    logging.info(f"Flask 应用运行在端口 {MEM_TOOL_PORT}...") # Flask app running on port
