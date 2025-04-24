import json
import socket

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
SQUAD_PROCESS_NAME = config['Configuration']['SQUAD_PROCESS_NAME']
COMMUNICATION_MODE = config['Configuration'].get('COMMUNICATION_MODE', 'http').lower()
SOCKET_PORT = int(config['Configuration'].get('SOCKET_PORT', 9090))
PROCESS_CHECK_INTERVAL = int(config['Configuration'].get('PROCESS_CHECK_INTERVAL', 30))  # 进程检查间隔，默认30秒

current_token = None
memory_config_received = False  # 新增标志，用于标记是否已从服务器接收到内存配置
process_monitoring_active = True  # 用于控制进程监控线程


class MemoryReader:
    def __init__(self):
        self.pm = None
        self.base_address = None

        self.initial_offset = None
        self.process_name = SQUAD_PROCESS_NAME
        self.team_offsets = {
            1: None,
            2: None
        }
        self.selected_pid = None
        self.current_dir = os.path.normpath(os.getcwd()).lower()
        self.connection_lock = threading.Lock()  # 添加锁，防止并发访问连接状态
        print(f"{['Current directory']}: {self.current_dir}")

    def update_memory_config(self, memory_config):
        try:
            if "initial_offset" in memory_config:
                offset_str = memory_config["initial_offset"]
                if isinstance(offset_str, str) and offset_str.startswith("0x"):
                    self.initial_offset = int(offset_str, 16)
                else:
                    self.initial_offset = int(offset_str)

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

            print("内存配置更新完成。")  # Memory config updated complete
            global memory_config_received
            memory_config_received = True
            return True
        except Exception as e:
            print(f"['Error updating memory config']: {str(e)}")
            return False

    def list_squad_processes(self):
        squad_processes = []
        logging.debug("开始查找 SquadGameServer.exe 进程...")  # Start list squad process
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['name'] == self.process_name:
                    proc_path = os.path.normpath(proc.info['exe']).lower()
                    proc_dir = os.path.dirname(proc_path)
                    logging.debug(
                        f"Found SquadGameServer.exe process: PID {proc.info['pid']}, Path {proc_path}")
                    if proc_dir == self.current_dir:
                        squad_processes.append({'pid': proc.info['pid'], 'directory': proc_dir})
                        print(f"Matched SquadGameServer.exe process: PID {proc.info['pid']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                print(f"'Error accessing process: {str(e)}")
                continue
        if not squad_processes:
            print("未找到匹配的 SquadGameServer.exe 进程。")  # No matched squad process found
        else:
            print(f"共找到 {len(squad_processes)} 个 SquadGameServer.exe 进程。")  # Found count squad process
        return squad_processes

    def select_process(self):
        print("开始选择进程...")  # Start select process
        processes = self.list_squad_processes()
        if not processes:
            error_msg = "No SquadGameServer.exe process found in current directory"
            print(f"{error_msg}: {self.current_dir}")
            raise Exception(error_msg)
        if len(processes) > 1:
            logging.warning(
                f"Multiple SquadGameServer.exe processes found: {len(processes)}，选择第一个。")  # Multiple squad process found, select first one
            self.selected_pid = processes[0]['pid']
        else:
            self.selected_pid = processes[0]['pid']
        print(f"Selected SquadGameServer.exe process: PID {self.selected_pid}")
        return True

    def check_config_received(self):
        if not memory_config_received or self.initial_offset is None or not all(self.team_offsets.values()):
            print("Memory configuration not received yet")
            raise Exception("Waiting for memory configuration from server")
        return True

    def get_offsets(self, team):
        self.check_config_received()
        print("get_offsets, team:", team)
        team = int(team)
        if team not in [1, 2]:
            raise ValueError("Team must be 1 or 2")
        if not self.team_offsets[team]:
            raise Exception("Memory configuration not received yet")
        return self.team_offsets[team]

    def is_process_alive(self):
        """检查当前选择的进程是否存在并且运行"""
        if not self.selected_pid:
            return False
        try:
            process = psutil.Process(self.selected_pid)
            return process.is_running() and process.name() == self.process_name
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            return False

    def connect(self):
        with self.connection_lock:
            print("尝试连接到游戏进程...")  # Trying to connect game process
            try:
                if not self.selected_pid or not self.is_process_alive():
                    if not self.select_process():
                        return False

                # 关闭现有的连接
                if self.pm:
                    try:
                        self.pm.close_process()
                    except:
                        pass
                    self.pm = None
                    self.base_address = None

                self.pm = pymem.Pymem()
                self.pm.open_process_from_id(self.selected_pid)
                module = pymem.process.module_from_name(self.pm.process_handle, self.process_name)
                if not module:
                    raise Exception("Could not find SquadGameServer.exe module")
                self.base_address = module.lpBaseOfDll
                print("连接游戏进程成功。")  # Connect game process success
                return True
            except Exception as e:
                print(f"Connection error: {str(e)}")
                print("连接游戏进程失败。")  # Connect game process failed
                self.selected_pid = None
                self.pm = None
                self.base_address = None
                return False

    def ensure_connection(self):
        """确保连接到游戏进程，如果没有连接或进程已退出，则尝试重新连接"""
        if not self.pm or not self.base_address or not self.is_process_alive():
            logging.warning("Process not found or exited, trying to reconnect")
            return self.connect()
        return True

    def follow_pointers(self, initial_addr, offsets):
        addr = initial_addr
        for i, offset in enumerate(offsets):
            try:
                ptr = self.pm.read_ulonglong(addr)
                addr = ptr + offset
            except pymem.exception.MemoryReadError:
                error_msg ="Failed to read memory"
                print(error_msg)
                raise Exception(error_msg)
        return addr

    def get_ticket_value(self, team):
        print(f"尝试获取队伍 {team} 的票数...")  # Trying to get team ticket value

        # 确保已从服务器接收到配置
        self.check_config_received()

        # 确保连接到游戏进程
        if not self.ensure_connection():
            raise Exception("Failed to connect to process")  # Already logged in connect()

        try:
            offsets = self.get_offsets(team)
        except ValueError as e:
            raise Exception(str(e))  # Message from get_offsets is already Chinese

        initial_addr = self.base_address + self.initial_offset
        target_addr = self.follow_pointers(initial_addr, offsets)
        try:
            value = self.pm.read_ulonglong(target_addr)
            print(f"队伍 {team} 的票数为: {value}")  # Team ticket value is
            return value
        except pymem.exception.MemoryReadError:
            error_msg = "Failed to read memory"
            print(error_msg)
            raise Exception(error_msg)

    def set_ticket_value(self, team, new_value):
        print(f"尝试设置队伍 {team} 的票数为: {new_value}...")  # Trying to set team ticket value
        team = int(team)
        new_value = int(new_value)
        # 确保已从服务器接收到配置
        self.check_config_received()

        # 确保连接到游戏进程
        if not self.ensure_connection():
            raise Exception("Failed to connect to process")  # Already logged in connect()

        try:
            offsets = self.get_offsets(team)
        except ValueError as e:
            raise Exception(str(e))  # Message from get_offsets is already Chinese
        try:
            new_value = int(new_value)
            if new_value < 0:
                raise ValueError("Value must be positive")
        except ValueError:
            raise Exception("Invalid value provided")
        initial_addr = self.base_address + self.initial_offset

        target_addr = self.follow_pointers(initial_addr, offsets)
        try:
            self.pm.write_ulonglong(target_addr, new_value)
            print(f"队伍 {team} 的票数已设置为: {new_value}")  # Team ticket value set to
            return True
        except pymem.exception.MemoryWriteError:
            error_msg = "Failed to write memory"
            print(error_msg)
            raise Exception(error_msg)


memory_reader = MemoryReader()


def send_heartbeat():
    global current_token
    while True:
        payload = {
            "server_id": SERVER_ID,
            "mem_tool_id": MEM_TOOL_ID,
            "server_ip": SERVER_IP,
            "version": VERSION,
            "communication_mode": COMMUNICATION_MODE,
            "mem_tool_port": MEM_TOOL_PORT if COMMUNICATION_MODE == "http" else SOCKET_PORT
        }
        try:
            print("[DEBUG] 发送心跳包...")
            response = requests.post(AUTH_SERVICE_URL, json=payload, verify=False, timeout=5)
            if response.status_code == 200:
                response_data = response.json()
                current_token = response_data["token"]
                print(f"[INFO] {'Heartbeat successful, token updated'}")
                # 处理内存配置信息
                if "memory_config" in response_data:
                    print("[INFO] 接收到内存配置信息，开始更新...")
                    if memory_reader.update_memory_config(response_data["memory_config"]):
                        print("[INFO] 内存配置更新成功")
                    else:
                        print("[ERROR] 内存配置更新失败")
            else:
                print(f"[WARNING] 心跳响应状态码: {response.status_code}")
        except requests.RequestException as e:
            print(f"[ERROR] {'Heartbeat failed'}: {e}")
        time.sleep(60)


def monitor_process():
    """监控游戏进程，如果进程退出则尝试重新连接新进程"""
    global process_monitoring_active
    print(
        f"{'Process monitoring started'}, {'Process check interval'}: {PROCESS_CHECK_INTERVAL}秒")

    while process_monitoring_active:
        if memory_reader.selected_pid:
            if not memory_reader.is_process_alive():
                logging.warning("Original process exited, searching for new process")
                # 尝试查找新进程
                processes = memory_reader.list_squad_processes()
                if processes:
                    new_pid = processes[0]['pid']
                    if new_pid != memory_reader.selected_pid:
                        print(f"{'New process detected, reconnecting'}: PID {new_pid}")
                        memory_reader.selected_pid = new_pid
                        memory_reader.connect()
        else:
            # 如果没有选择进程，尝试选择并连接
            try:
                memory_reader.select_process()
                memory_reader.connect()
            except Exception as e:
                print(f"尝试连接新进程失败: {str(e)}")

        time.sleep(PROCESS_CHECK_INTERVAL)


@app.route('/mem_tool/set/ticket', methods=['GET'])
def set_ticket():
    print("Endpoint '/mem_tool/set/ticket' 被访问")  # Endpoint set ticket accessed
    token = request.headers.get('X-Auth-Token')
    if token != current_token or current_token is None:
        logging.warning("未授权访问尝试")  # Unauthorized access attempt
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    try:
        if not memory_config_received:
            return jsonify({'status': 'error', 'message': 'Memory configuration not received yet'}), 503

        team = request.args.get('team')
        value = request.args.get('value')
        print(f"请求参数：队伍={team}, 数值={value}")  # Request params: team, value
        if not team or not value:
            logging.warning('Missing required parameters')
            return jsonify({'status': 'error', 'message': 'Missing required parameters'}), 400
        team = int(team)
        if team not in [1, 2]:
            logging.warning('Invalid team number')
            return jsonify({'status': 'error', 'message': 'Invalid team number'}), 400
        memory_reader.set_ticket_value(team, value)
        current_value = memory_reader.get_ticket_value(team)
        print(f"票数已设置，当前队伍 {team} 票数为: {current_value}")  # Ticket set, current team ticket value
        return jsonify({
            'status': 'success',
            'message': 'Value updated successfully',
            'team': team,
            'value': current_value
        })
    except Exception as e:
        print(f"{'Error in set_ticket'}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/mem_tool/get/ticket', methods=['GET'])
def get_ticket():
    print("Endpoint '/mem_tool/get/ticket' 被访问")  # Endpoint get ticket accessed
    token = request.headers.get('X-Auth-Token')
    if token != current_token or current_token is None:
        logging.warning("未授权访问尝试")  # Unauthorized access attempt
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    try:
        if not memory_config_received:
            return jsonify({'status': 'error', 'message': 'Memory configuration not received yet'}), 503

        team = request.args.get('team')
        print(f"请求参数：队伍={team}")  # Request param: team
        if not team:
            logging.warning('Missing team parameter')
            return jsonify({'status': 'error', 'message': 'Missing team parameter'}), 400
        team = int(team)
        if team not in [1, 2]:
            logging.warning('Invalid team number')
            return jsonify({'status': 'error', 'message': 'Invalid team number'}), 400
        value = memory_reader.get_ticket_value(team)
        print(f"获取到队伍 {team} 的票数为: {value}")  # Got team ticket value
        return jsonify({'status': 'success', 'team': team, 'value': value})
    except Exception as e:
        print(f"{'Error in get_ticket'}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


def socket_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', SOCKET_PORT))
        s.listen()
        print(f"Socket 服务器启动，监听端口 {SOCKET_PORT}...")
        while True:
            conn, addr = s.accept()
            print(f"Socket 客户端连接: {addr}")
            try:
                data = conn.recv(1024).decode('utf-8')
                request = json.loads(data)
                # 验证 Token
                if request.get('token') != current_token:
                    response = {'status': 'error', 'message': 'Unauthorized'}
                else:
                    action = request.get('action')
                    team = request.get('team')
                    value = request.get('value')
                    print(f"socket request: {action} {team} {value}")
                    # 处理请求
                    if action == 'set_ticket':
                        memory_reader.set_ticket_value(team, value)
                        current_value = memory_reader.get_ticket_value(team)
                        response = {'status': 'success', 'value': current_value}
                    elif action == 'get_ticket':
                        current_value = memory_reader.get_ticket_value(team)
                        response = {'status': 'success', 'value': current_value}
                    else:
                        response = {'status': 'error', 'message': '无效操作'}
                conn.send(json.dumps(response).encode('utf-8'))
            except Exception as e:
                print(f"Socket 请求处理失败: {str(e)}")
                conn.send(json.dumps({'status': 'error', 'message': str(e)}).encode('utf-8'))
            finally:
                conn.close()


if __name__ == '__main__':

    print("[INFO] Squad ICU Mem Tool 服务启动...")
    if not memory_reader.connect():
        print(f"[ERROR] {'Failed to initialize connection to game process'}")
    else:
        print("[INFO] 成功初始化与游戏进程的连接。")

    # 启动心跳线程
    threading.Thread(target=send_heartbeat, daemon=True).start()
    print("[INFO] 心跳线程已启动。")

    # 启动进程监控线程
    process_monitor_thread = threading.Thread(target=monitor_process, daemon=True)
    process_monitor_thread.start()

    print("[INFO] 等待从服务器接收内存配置...")

    print(f"[INFO]通信方式: {COMMUNICATION_MODE}")
    if COMMUNICATION_MODE == 'http':
        app.run(host='0.0.0.0', port=MEM_TOOL_PORT)
        print(f"[INFO]web 应用运行在端口 {MEM_TOOL_PORT}...")  # Flask app running on port
    elif COMMUNICATION_MODE == 'socket':
        socket_thread = threading.Thread(target=socket_server, daemon=True)
        socket_thread.start()
        socket_thread.join()
    else:
        print("[ERROR] 无效的通信模式配置")

    # 停止进程监控
    process_monitoring_active = False
