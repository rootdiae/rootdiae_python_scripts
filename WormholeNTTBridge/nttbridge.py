import os
import sys
import time
import json
import base64
import logging
import requests
import yaml  #安的不是这个库，是pip install pyyaml -i https://pypi.tuna.tsinghua.edu.cn/simple
from decimal import Decimal, getcontext
from web3 import Web3
from dotenv import load_dotenv
from web3.middleware import ExtraDataToPOAMiddleware
import asyncio
import websockets
import random
from eth_abi import decode
from eth_utils import decode_hex
import threading
import queue

# ========== 工具函数 ==========

def load_config(path="config1.yaml"):
    """
    加载YAML配置文件，返回配置字典
    """
    with open(path, "r") as f:
        return yaml.safe_load(f)

def setup_logger(log_level="INFO", log_file="wormhole.log"):
    """
    配置日志系统，日志同时输出到控制台和文件
    """
    logger = logging.getLogger("wormhole")
    logger.setLevel(getattr(logging, log_level.upper()))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    # 防止重复添加handler
    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(ch)
    return logger

def to_bytes32(address: str) -> bytes:
    """
    将以太坊地址转为bytes32格式，左侧补零
    """
    addr = Web3.to_bytes(hexstr=address)
    return addr.rjust(32, b'\0')

def amount_to_min_unit(amount_str, decimals):
    """
    将十进制字符串金额转换为最小单位整数
    """
    getcontext().prec = 80
    return int(Decimal(amount_str) * Decimal(10 ** decimals))

def checksum(address):
    """
    将地址转换为EIP-55校验格式
    """
    return Web3.to_checksum_address(address)

def sleep_with_log(seconds, logger):
    """
    日志输出休眠信息，并休眠指定秒数
    """
    logger.debug(f"休眠 {seconds} 秒...")
    time.sleep(seconds)

def init_web3(rpc_url, enable_poa_middleware=False):  # 新增参数：是否启用POA中间件
    """
    初始化web3对象，连接指定RPC，连接失败抛出异常
    """
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
    
    # 根据开关动态注入POA中间件
    if enable_poa_middleware:
        # 仅POA链注入中间件，禁用extraData长度校验
        # layer=0表示最内层中间件，优先处理区块数据解析
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        logging.getLogger("wormhole").debug(f"已为RPC {rpc_url} 注入POA中间件")
    
    if not w3.is_connected():
        raise RuntimeError(f"Web3 连接失败: {rpc_url}")
    return w3

def build_tx_with_gas_params(w3, tx_dict, logger):
    """
    构建交易参数：
    - 非 EIP-1559 链：使用 gasPrice
    - EIP-1559 链：强制使用 maxFeePerGas / maxPriorityFeePerGas
      priority fee 为 0 时使用兜底值，而不是回退
    """

    tx = tx_dict.copy()
    tx["chainId"] = w3.eth.chain_id

    FALLBACK_PRIORITY_FEE = 1000000      # 0.001 gwei
    BASE_FEE_MULTIPLIER = 1.2

    try:
        # ---------- 1. 探测 baseFee ----------
        latest_block = w3.eth.get_block("latest")  # 获取最新区块信息
        base_fee = latest_block.get("baseFeePerGas", 0)

        # ---------- 2. 非 EIP-1559 链 ----------
        if base_fee is None or base_fee == 0:
            logger.info("检测到非 EIP-1559 链，使用 gasPrice")

            gas_price = w3.eth.gas_price  # 获取gas价格，构建交易gasfee必须的rpc调用，不可省略
            tx["gasPrice"] = gas_price

            # 清理 EIP-1559 字段
            tx.pop("maxFeePerGas", None)
            tx.pop("maxPriorityFeePerGas", None)

            logger.info(f"gasPrice = {Web3.from_wei(gas_price, 'gwei')} gwei")
            return tx

        # ---------- 3. EIP-1559 链 ----------
        try:
            priority_fee = int(w3.eth.max_priority_fee)  # 获取建议的 priority fee，构建交易gasfee必须的rpc调用，不可省略
        except Exception:
            priority_fee = 0

        if priority_fee <= 0:
            logger.warning(
                f"RPC 返回 maxPriorityFeePerGas={priority_fee}，使用兜底值 {FALLBACK_PRIORITY_FEE}"
            )
            priority_fee = FALLBACK_PRIORITY_FEE

        max_fee = int(base_fee * BASE_FEE_MULTIPLIER) + priority_fee

        tx["maxFeePerGas"] = max_fee
        tx["maxPriorityFeePerGas"] = priority_fee

        # 清理 legacy 字段
        tx.pop("gasPrice", None)

        logger.info(
            "使用 EIP-1559 参数构建交易: "
            f"baseFee={Web3.from_wei(base_fee, 'gwei')} gwei, "
            f"maxFeePerGas={Web3.from_wei(max_fee, 'gwei')} gwei, "
            f"maxPriorityFeePerGas={Web3.from_wei(priority_fee, 'gwei')} gwei"
        )

        return tx

    except Exception as e:
        logger.error(f"构建 gas 参数失败: {e}")
        raise

# 源链digest获取函数
def get_digest_from_src_tx(w3_src, src_tx_hash, logger):
    """
    从源链交易哈希获取digest（TransferSent事件的topic1）
    """
    logger.info(f"正在获取源链交易 {src_tx_hash} 的digest...")
    try:
        receipt = w3_src.eth.get_transaction_receipt(src_tx_hash)
        logs = receipt["logs"]
        
        # 为了兼容的不同的节点，定义多个可能的topic0格式（带或不带0x前缀）
        target_topic0_variants = [
            "0x3e6ae56314c6da8b461d872f41c6d0bb69317b9d0232805aaccfa45df1a16fa0",
            "3e6ae56314c6da8b461d872f41c6d0bb69317b9d0232805aaccfa45df1a16fa0"
        ]
        
        for log in logs:
            if len(log["topics"]) >= 2:
                actual_topic0 = log["topics"][0].hex()  # HexBytes的hex()方法返回不带0x的字符串
                
                # 检查是否匹配任一格式
                for variant in target_topic0_variants:
                    # 统一转换为小写进行比较
                    variant_normalized = variant.lower().replace("0x", "")
                    actual_normalized = actual_topic0.lower()
                    
                    if variant_normalized == actual_normalized:
                        digest = log["topics"][1].hex()
                        logger.info(f"已获取digest: {digest}")
                        return digest
        
        logger.error("未找到TransferSent事件，无法获取digest")
        return None
    except Exception as e:
        logger.error(f"获取digest失败: {e}")
        return None


class DstChainVAAWatcherThread:
    """
    目标链VAA事件订阅类（线程版本）
    用于在单独线程中运行WebSocket监听
    订阅MessageAttestedTo事件（在manager合约发出）
    """
    
    def __init__(self, config, digest, logger, is_received_dict, stop_event):
        self.config = config
        self.logger = logger
        self.digest = digest.lower().replace("0x", "")
        self.is_received_dict = is_received_dict
        self.stop_event = stop_event
        self.dst = config["dst"]
        self.wss_endpoints = self.dst["wss_endpoints"]
        
        # 订阅MessageAttestedTo事件
        self.topics = "0x35a2101eaac94b493e0dfca061f9a7f087913fde8678e7cde0aca9897edba0e5".lower()
        
        # 获取manager合约地址
        self.manager_address = self.dst["ntt_manager"]["address"].lower()
        
        # 使用manager ABI
        self.manager_abi_path = self.dst["ntt_manager"]["abi_path"]
        
        self.transceivers = self.dst["transceivers"]
        self.threshold = int(self.dst["threshold"])
        
        # 构建地址到名称的映射，用于后续匹配：transceiver地址 -> name的映射
        self.addr2name = {t["address"].lower(): t["name"] for t in self.transceivers}
        
        # 事件名称MessageAttestedTo从配置文件里获取
        self.ntt_manager_cfg = self.dst["ntt_manager"]
        self.methods = self.ntt_manager_cfg["methods"]
        self.event_name = self.methods["MessageAttestedTo"]
        self.abi_cache = {}
    
    def load_event_abi(self, abi_path):
        """加载并缓存ABI，现在加载manager ABI中的MessageAttestedTo事件"""
        if abi_path in self.abi_cache:
            return self.abi_cache[abi_path]
        
        with open(abi_path, "r") as f:
            abi = json.load(f)
        
        # 在manager ABI中查找MessageAttestedTo事件
        for item in abi:
            if item.get("type") == "event" and item.get("name") == self.event_name:
                self.abi_cache[abi_path] = item
                return item
        
        raise ValueError(f"ABI文件{abi_path}未找到事件{self.event_name}")
    
    def decode_event_data(self, event_data, abi_path):
        """
        解码MessageAttestedTo事件data字段
        事件结构：digest (bytes32), transceiver (address), index (uint8)
        返回：(digest_hex, transceiver_address)
        """
        try:
            abi = self.load_event_abi(abi_path)
            inputs = abi["inputs"]
            
            # MessageAttestedTo事件的所有参数都是非indexed的
            non_indexed_types = [i["type"] for i in inputs if not i["indexed"]]
            
            # 检查data字段是否存在且不为空
            if not event_data.get("data") or event_data["data"] == "0x":
                self.logger.warning("事件data字段为空，跳过解码")
                return None, None
            
            # 解码data字段
            data_bytes = decode_hex(event_data["data"])
            
            # 使用 eth_abi.decode 函数解码
            # address 类型会被解码为字符串，bytes32 会被解码为 bytes
            decoded = decode(non_indexed_types, data_bytes)
            
            # 根据ABI顺序提取参数
            # MessageAttestedTo事件的参数顺序：digest(bytes32), transceiver(address), index(uint8)
            if len(decoded) >= 2:
                digest_value = decoded[0]  # bytes32 -> bytes
                transceiver_value = decoded[1]  # address -> string
                # index字段为第三个参数，但我们不需要
                # index = decoded[2] if len(decoded) > 2 else 0
                
                # ========== 处理digest ==========
                # digest应该是bytes32类型，转换为十六进制字符串
                if isinstance(digest_value, bytes):
                    if len(digest_value) != 32:
                        self.logger.warning(f"digest长度异常，预期32字节，实际{len(digest_value)}字节")
                        return None, None
                    digest_hex = digest_value.hex().lower()  # 统一小写、无0x
                else:
                    self.logger.warning(f"digest类型异常，预期bytes，实际{type(digest_value)}: {digest_value}")
                    return None, None
                
                # ========== 处理transceiver地址 ==========
                # address类型可能被解码为字符串或bytes，需要处理两种情况
                transceiver_address = None
                
                if isinstance(transceiver_value, str):
                    # 已经是字符串格式的地址
                    try:
                        # 转换为checksum地址，然后转小写
                        transceiver_address = Web3.to_checksum_address(transceiver_value).lower()
                    except Exception as e:
                        self.logger.warning(f"转换transceiver地址失败: {e}")
                        return None, None
                        
                elif isinstance(transceiver_value, bytes):
                    # 如果是bytes格式（20字节），转换为字符串
                    if len(transceiver_value) == 20:
                        try:
                            transceiver_address = Web3.to_checksum_address(transceiver_value.hex()).lower()
                        except Exception as e:
                            self.logger.warning(f"转换transceiver bytes地址失败: {e}")
                            return None, None
                    else:
                        self.logger.warning(f"transceiver bytes长度异常，预期20字节，实际{len(transceiver_value)}字节")
                        return None, None
                else:
                    self.logger.warning(f"transceiver地址类型异常，预期str或bytes，实际{type(transceiver_value)}: {transceiver_value}")
                    return None, None
                
                self.logger.debug(f"成功解码: digest={digest_hex}, transceiver={transceiver_address}")
                return digest_hex, transceiver_address
            else:
                self.logger.warning(f"解码参数数量不足，预期至少2个，实际{len(decoded)}个")
                return None, None
                
        except Exception as e:
            self.logger.error(f"解码MessageAttestedTo事件数据失败: {e}", exc_info=True)
            return None, None
    
    async def ping_keepalive(self, websocket, node_url):
        """定时发送ping帧，新增CancelledError捕获，实现优雅退出"""
        try:
            while not self.stop_event.is_set():
                await asyncio.sleep(20)
                if self.stop_event.is_set():
                    break
                try:
                    await websocket.ping()
                    self.logger.info(f"向节点 {node_url} 发送保活ping帧")
                except (websockets.exceptions.ConnectionClosed, asyncio.CancelledError):
                    break
                except Exception as e:
                    self.logger.debug(f"发送ping失败: {e}")
                    break
        except asyncio.CancelledError:
            # 捕获任务取消异常，优雅退出
            self.logger.debug(f"ping保活任务被主动取消（节点{node_url}连接断开）")
        except Exception as e:
            self.logger.debug(f"ping保活任务异常: {e}")
    
    async def create_subscriptions(self, websocket):
        """
        创建订阅
        只创建manager合约的MessageAttestedTo事件订阅
        """
        subscription_mapping = {}
        subscription_id = 1
        
        params = {
            "jsonrpc": "2.0",
            "id": subscription_id,
            "method": "eth_subscribe",
            "params": [
                "logs",
                {
                    "address": self.manager_address,  # 订阅manager合约地址
                    "topics": [self.topics] # MessageAttestedTo事件的topic0
                }
            ]
        }
        

        await websocket.send(json.dumps(params))
        resp = await websocket.recv()
        resp_data = json.loads(resp)
        
        if "error" in resp_data:
            self.logger.error(f"订阅manager合约MessageAttestedTo事件失败: {resp_data['error']}")
        else:
            sub_id = resp_data["result"]
            # 映射订阅ID到manager地址（虽然只有一个，但保持结构一致）
            subscription_mapping[sub_id] = self.manager_address
            self.logger.info(f"订阅成功: manager合约 地址: {self.manager_address} 订阅ID: {sub_id}")
        
        return subscription_mapping
    
    async def listen(self, websocket, subscription_mapping, node_url):
        """
        监听事件推送，实时更新共享状态字典
        处理MessageAttestedTo事件，通过transceiver地址匹配
        """
        try:
            while not self.stop_event.is_set():
                try:
                    # 使用短超时，以便频繁检查stop_event
                    message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    
                    # 打印节点返回的完整原始数据
                    self.logger.debug(f"【节点原始数据】{node_url} 返回完整数据: {message}")
                    
                    # 解析JSON数据
                    data = json.loads(message)
                    self.logger.debug(f"【JSON解析后】{node_url} 结构化数据: {json.dumps(data, indent=2)}")

                    # 判断是否为订阅事件推送
                    if "method" in data and data["method"] == "eth_subscription":
                        self.logger.debug(f"【事件类型校验】匹配到 eth_subscription 订阅事件，开始处理")
                        sub_id = data["params"]["subscription"]
                        event_data = data["params"]["result"]
                        address = event_data.get("address", "").lower()
                        self.logger.debug(f"【事件基础信息】订阅ID: {sub_id} | 触发合约地址: {address}")

                        # 校验订阅ID和合约地址，现在只订阅manager合约，所以地址必须是manager地址
                        if sub_id in subscription_mapping and address == self.manager_address:
                            self.logger.debug(f"【订阅/地址校验】通过 → 订阅ID属于manager | 合约地址是manager地址")
                            
                            # 解码MessageAttestedTo事件
                            digest_hex, transceiver_address = self.decode_event_data(event_data, self.manager_abi_path)
                            
                            if digest_hex and transceiver_address:
                                self.logger.debug(f"【事件解码结果】digest: {digest_hex} | transceiver地址: {transceiver_address}")
                                
                                # 校验digest是否匹配
                                target_digest = self.digest
                                current_digest = digest_hex.lower().replace("0x", "")
                                
                                if current_digest == target_digest:
                                    self.logger.debug(f"【Digest校验】完全匹配 → 目标:{target_digest} | 当前:{current_digest}")
                                    
                                    # 通过transceiver地址匹配对应的transceiver
                                    # 在addr2name映射中查找transceiver名称
                                    if transceiver_address in self.addr2name:
                                        transceiver_name = self.addr2name[transceiver_address]
                                        
                                        # 标记该transceiver已收到MessageAttestedTo事件
                                        if not self.is_received_dict.get(transceiver_name, False):
                                            self.is_received_dict[transceiver_name] = True
                                            self.logger.info(f"收到 transceiver {transceiver_name} 的MessageAttestedTo事件，digest匹配，已标记为True")
                                            
                                            # 检查是否达到threshold
                                            received_count = sum(1 for v in self.is_received_dict.values() if v)
                                            self.logger.info(f"当前已收到事件数量: {received_count} / threshold={self.threshold}")
                                            
                                            if received_count >= self.threshold:
                                                self.logger.info(f"已达到threshold={self.threshold}，自动停止监听")
                                                # 设置停止事件
                                                self.stop_event.set()
                                                return  # 立即返回，退出监听循环
                                        else:
                                            self.logger.debug(f"transceiver {transceiver_name} 已标记为True，跳过重复事件")
                                    else:
                                        # transceiver地址不在配置列表中，可能是其他合约的事件
                                        self.logger.warning(f"未知的transceiver地址: {transceiver_address}，跳过事件")
                                else:
                                    # digest不匹配，跳过事件
                                    self.logger.debug(f"【Digest校验失败】不匹配 → 目标digest:{target_digest} | 事件digest:{current_digest}，跳过事件")
                            else:
                                # 解码失败，跳过事件
                                self.logger.warning(f"【事件解码失败】无法从事件data中解析digest和transceiver，跳过当前事件")
                        else:
                            # 订阅ID或地址不匹配，跳过事件
                            self.logger.debug(f"【订阅/地址过滤】跳过当前事件 → 订阅ID{sub_id}不在映射中 OR 地址{address}不是manager地址")
                    else:
                        # 非订阅事件，跳过
                        self.logger.debug(f"【事件类型过滤】收到非eth_subscription数据 → 实际method: {data.get('method', '无method字段')}，跳过")

                except asyncio.TimeoutError:
                    # 超时属于正常轮询，避免日志刷屏
                    continue
                except websockets.exceptions.ConnectionClosedError:
                    self.logger.warning(f"【连接异常】{node_url} WebSocket连接断开，准备重连...")
                    break
                except asyncio.CancelledError:
                    self.logger.debug(f"【任务终止】{node_url} 监听任务被主动取消")
                    break
                except json.JSONDecodeError as e:
                    self.logger.error(f"【数据解析失败】{node_url} 返回数据非合法JSON → 原始数据:{message} | 错误:{str(e)}")
                    continue
                except Exception as e:
                    self.logger.warning(f"【监听异常】{node_url} 处理事件时发生异常: {str(e)}", exc_info=True)
                    continue
        except Exception as e:
            self.logger.error(f"【监听任务崩溃】{node_url} 监听线程整体异常: {str(e)}", exc_info=True)

    async def run(self):
        """运行WebSocket监听，新增任务清理逻辑"""
        max_retries = 5
        retry_count = 0
        reconnect_delay = 1
        
        while not self.stop_event.is_set() and retry_count < max_retries:
            # 检查是否已达到threshold
            received_count = sum(1 for v in self.is_received_dict.values() if v)
            if received_count >= self.threshold:
                self.logger.info(f"已达到threshold={self.threshold}，停止监听")
                self.stop_event.set()  # 也设置stop_event，确保其他逻辑也能检测到
                return
            
            connected = False
            for node_url in self.wss_endpoints:
                # 每次尝试连接前检查stop_event
                if self.stop_event.is_set():
                    self.logger.info("stop_event已设置，停止尝试连接")
                    return
                    
                ping_task = None  # 初始化任务变量，避免未定义
                try:
                    self.logger.info(f"尝试连接wss节点: {node_url}")
                    async with websockets.connect(
                        node_url,
                        ping_interval=10,
                        ping_timeout=5,
                        close_timeout=3
                    ) as websocket:
                        self.logger.info(f"已连接到wss节点: {node_url}")
                        connected = True
                        retry_count = 0
                        
                        # 创建订阅
                        subscription_mapping = await self.create_subscriptions(websocket)
                        
                        # 启动ping任务
                        ping_task = asyncio.create_task(self.ping_keepalive(websocket, node_url))
                        await self.listen(websocket, subscription_mapping, node_url)
                        
                        # listen()返回后，检查stop_event
                        if self.stop_event.is_set():
                            self.logger.info(f"监听任务已完成，退出节点 {node_url}")
                            return
                except Exception as e:
                    self.logger.warning(f"连接wss节点 {node_url} 失败: {e}")
                    continue
                finally:
                    # 无论是否异常，都取消ping任务，避免残留
                    if ping_task and not ping_task.done():
                        ping_task.cancel()
                        try:
                            await ping_task
                        except Exception:
                            pass
            
            # 重连逻辑
            if not connected:
                retry_count += 1
                if retry_count < max_retries:
                    self.logger.warning(f"所有节点连接失败，{reconnect_delay}秒后重试 ({retry_count}/{max_retries})...")
                    await asyncio.sleep(reconnect_delay)
                    reconnect_delay = min(reconnect_delay * 2, 30)
                else:
                    self.logger.error(f"达到最大重试次数 {max_retries}，停止重连")
                    break

class ConcurrentVAAPollerAndWatcher:
    """
    并发管理 VAA 轮询和 WebSocket 订阅
    使用多线程实现真正的并行，避免异步切换延迟
    """
    def __init__(self, config, logger, src_tx_hash, min_unit_amount, recipient_on_dst, wormhole_dst_chain_id, token):
        self.config = config
        self.logger = logger
        self.src_tx_hash = src_tx_hash
        self.min_unit_amount = min_unit_amount
        self.recipient_on_dst = recipient_on_dst
        self.wormhole_dst_chain_id = wormhole_dst_chain_id
        self.token = token
        
        # 状态变量
        self.vaa = None
        self.parsed_payload = None
        self.vaa_ready = threading.Event()
        self.should_stop = threading.Event()
        self.result_queue = queue.Queue()
        
        # 提前获取digest
        self.digest = None
        self._get_digest()
    
    def get_digest(self):
        """返回已获取的digest，避免重复获取"""
        return self.digest
    
    def _get_digest(self):
        """获取 digest"""
        try:
            src_rpc = self.config["src"]["rpc"]
            w3_src = Web3(Web3.HTTPProvider(src_rpc))
            
            for attempt in range(3):
                self.digest = get_digest_from_src_tx(w3_src, self.src_tx_hash, self.logger)
                if self.digest:
                    break
                self.logger.warning(f"未获取到 digest，10秒后重试({attempt+1}/3)...")
                time.sleep(10)
            
            if not self.digest:
                raise RuntimeError("无法获取 digest")
                
        except Exception as e:
            self.logger.error(f"获取 digest 失败: {e}")
            raise
    
    def _poll_vaa_thread(self):
        """VAA轮询线程"""
        try:
            self.logger.debug("VAA轮询线程启动")
            vaa, parsed_payload = self._poll_and_validate_vaa_sync()
            if vaa:
                self.vaa = vaa
                self.parsed_payload = parsed_payload
                self.vaa_ready.set()  # 通知主线程VAA已就绪
                self.result_queue.put(("success", vaa, parsed_payload))
            else:
                self.result_queue.put(("error", None, None))
        except Exception as e:
            self.logger.error(f"VAA轮询线程异常: {e}")
            self.result_queue.put(("error", None, None))
    
    def _poll_and_validate_vaa_sync(self):
        """
        同步版本的VAA轮询和校验函数
        使用同步requests库
        """
        wormholescan_api_base = self.config["runtime"]["wormholescan_api_base"]
        vaa_poll_interval = float(self.config["runtime"]["vaa_poll_interval_seconds"])
        vaa_alert_interval = int(self.config["runtime"]["vaa_alert_interval_seconds"])
        vaa_alert_timeout = int(self.config["runtime"]["vaa_alert_timeout_seconds"])
        
        vaa = None
        parsed_payload = None
        start_time = time.time()
        last_alert_time = 0
        
        while not self.should_stop.is_set():
            try:
                # 查询WormholeScan API
                resp = requests.get(
                    f"{wormholescan_api_base}/vaas/?page=0&pageSize=5&sortOrder=ASC&txHash={self.src_tx_hash}&parsedPayload=true",
                    headers={"accept": "application/json"},
                    timeout=10
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    vaa_data_list = data.get("data", [])
                    
                    if not vaa_data_list:
                        self.logger.info("vaa还未签名，继续轮询获取中...")
                    else:
                        for vaa_data in vaa_data_list:
                            if "payload" in vaa_data and vaa_data["payload"] is not None:
                                vaa = vaa_data["vaa"]
                                parsed_payload = vaa_data["payload"]
                                self.logger.info(f"找到带payload的VAA: {vaa[:32]}... (base64)")
                                break
                    
                    if vaa and parsed_payload:
                        # 校验 VAA
                        self.logger.info("开始解析并校验 VAA...")
                        try:
                            ntt_message = parsed_payload.get("nttMessage", {})
                            trimmed_amount = ntt_message.get("trimmedAmount", {})
                            amount_str = trimmed_amount.get("amount")
                            if amount_str is None:
                                self.logger.error("VAA 校验失败：未找到 trimmedAmount.amount 字段")
                                return None, None
                            
                            trimmed_decimals = trimmed_amount.get("decimals")
                            if trimmed_decimals != self.token["wormhole_declaims"]:
                                self.logger.error(f"VAA 校验失败：trimmedAmount.decimals 不是{self.token['wormhole_declaims']}，实际为 {trimmed_decimals}")
                                return None, None
                            
                            normalized_amount = int(amount_str)
                            scale = 10 ** (self.token["decimals"] - self.token["wormhole_declaims"])
                            reconstructed_amount = normalized_amount * scale
                            
                            if str(reconstructed_amount) != str(self.min_unit_amount):
                                self.logger.error(f"VAA 金额校验失败：解析值 {reconstructed_amount} vs 预期值 {self.min_unit_amount}")
                                return None, None
                            else:
                                token_decimals = self.token["decimals"]
                                decimal_amount = Decimal(self.min_unit_amount) / (10 ** token_decimals)
                                decimal_amount = decimal_amount.normalize()
                                self.logger.info(f"VAA金额校验成功: {decimal_amount} {self.token['symbol']} (最小单位: {self.min_unit_amount}")
                            
                            to_address = ntt_message.get("to", "")
                            if not to_address:
                                self.logger.error("VAA 校验失败：未找到 nttMessage.to 字段")
                                return None, None
                            
                            if to_address.lower()[-40:] != self.recipient_on_dst.lower()[-40:]:
                                self.logger.error(f"VAA 接收地址校验失败：解析值 {to_address} vs 预期值 {self.recipient_on_dst}")
                                return None, None
                            else:
                                self.logger.info(f"VAA地址校验成功: {to_address}")
                            
                            to_chain = ntt_message.get("toChain")
                            if to_chain is None:
                                self.logger.error("VAA 校验失败：未找到 nttMessage.toChain 字段")
                                return None, None
                            
                            if int(to_chain) != self.wormhole_dst_chain_id:
                                self.logger.error(f"VAA 目标链ID校验失败：解析值 {to_chain} vs 预期值 {self.wormhole_dst_chain_id}")
                                return None, None
                            else:
                                self.logger.info(f"VAA目标链ID校验成功: {to_chain}")
                            
                            self.logger.info("VAA 所有校验通过")
                            return vaa, parsed_payload
                            
                        except Exception as e:
                            self.logger.error(f"VAA 校验失败: {e}", exc_info=True)
                            return None, None
                    else:
                        elapsed = int(time.time() - start_time)
                        minutes = elapsed // 60
                        seconds = elapsed % 60
                        if elapsed - last_alert_time >= vaa_alert_interval and elapsed >= vaa_alert_timeout:
                            self.logger.warning(f"等待带payload的VAA已超过 {minutes} 分 {seconds} 秒...")
                            last_alert_time = elapsed
                        time.sleep(vaa_poll_interval)
                else:
                    self.logger.error(f"WormholeScan API响应状态码异常: {resp.status_code}，响应内容: {resp.text}")
                    time.sleep(vaa_poll_interval)
                    
            except Exception as e:
                self.logger.error(f"轮询VAA时发生异常: {str(e)}")
                time.sleep(vaa_poll_interval)
        
        return None, None
    
    def _watcher_thread(self, is_received_dict, stop_event):
        """WebSocket监听线程"""
        try:
            self.logger.debug("WebSocket监听线程启动")
            # 创建新的事件循环用于这个线程
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # 创建watcher
            watcher = DstChainVAAWatcherThread(
                self.config, 
                self.digest, 
                self.logger, 
                is_received_dict,
                stop_event
            )
            
            # 运行watcher
            loop.run_until_complete(watcher.run())
            
        except Exception as e:
            self.logger.error(f"WebSocket监听线程异常: {e}")
    
    def run(self):
        """
        启动并发的VAA轮询和WebSocket监听
        返回: (vaa, parsed_payload, is_received_dict, stop_event)
        """
        # 共享状态字典，用于线程间通信
        is_received_dict = {}
        for t in self.config["dst"]["transceivers"]:
            is_received_dict[t["name"]] = False
        
        # 停止事件，用于通知监听线程退出
        stop_event = threading.Event()
        
        # 启动VAA轮询线程
        vaa_thread = threading.Thread(target=self._poll_vaa_thread, daemon=True)
        vaa_thread.start()
        
        # 启动WebSocket监听线程
        watcher_thread = threading.Thread(
            target=self._watcher_thread, 
            args=(is_received_dict, stop_event),
            daemon=True
        )
        watcher_thread.start()
        
        # 等待VAA就绪
        self.logger.debug("等待VAA就绪...")
        self.vaa_ready.wait()
        
        # 检查是否有VAA
        status, vaa, parsed_payload = self.result_queue.get(timeout=5)
        if status != "success":
            self.logger.error("VAA获取失败")
            stop_event.set()  # 通知监听线程退出
            return None, None, None, None
        
        # 返回结果，但不停止监听线程
        return vaa, parsed_payload, is_received_dict, stop_event
    
    def stop(self, stop_event):
        """停止所有线程"""
        self.should_stop.set()
        stop_event.set()

# 结果确认主流程
def confirm_result(config, w3_src, w3_dst, logger, digest=None):
    """
    统一的结果确认流程，适用于所有模式
    """
    dst = config["dst"]
    transfer_params = config["transfer_params"]
    ntt_manager_cfg = dst["ntt_manager"]
    methods = ntt_manager_cfg["methods"]
    amount = Decimal(transfer_params["amount"])
    src_chain_id = config["src"]["wormhole_chain_id"]
    private_key = os.getenv(config["auth"]["private_key_env"])
    account = w3_src.eth.account.from_key(private_key)
    from_address = account.address

    # 加载manager合约
    with open(ntt_manager_cfg["abi_path"], "r") as f:
        manager_abi = f.read()
    manager = w3_dst.eth.contract(address=checksum(ntt_manager_cfg["address"]), abi=manager_abi)

    # 确保digest是bytes32格式（bytes类型）
    if isinstance(digest, str):
        if digest.startswith('0x'):
            digest_bytes32 = Web3.to_bytes(hexstr=digest)
        else:
            digest_bytes32 = Web3.to_bytes(hexstr=f"0x{digest}")
    elif isinstance(digest, bytes):
        digest_bytes32 = digest
    else:
        logger.error(f"未知的digest类型: {type(digest)}")
        return

    logger.info(f"使用digest (bytes32格式, 长度: {len(digest_bytes32)}): 0x{digest_bytes32.hex()}")

    # 1. transceiverAttestedToMessage 检查
    logger.info("开始检查所有transceiver的attestation状态...")
    attested_ok = False
    for attempt in range(3):
        all_attested = True
        for transceiver_cfg in dst["transceivers"]:
            idx = transceiver_cfg["index"]
            try:
                # 注意参数顺序：digest, index
                attested = getattr(manager.functions, methods["transceiverAttestedToMessage"])(
                    digest_bytes32, idx
                ).call()
                logger.info(f"transceiver index={idx} attested={attested}")
                if not attested:
                    all_attested = False
            except Exception as e:
                logger.error(f"查询transceiverAttestedToMessage失败: {e}")
                all_attested = False
        if all_attested:
            attested_ok = True
            break
        else:
            logger.warning(f"有transceiver未attest，10秒后重试({attempt+1}/3)...")
            sleep_with_log(10, logger)
    if not attested_ok:
        logger.error("部分transceiver未attest，流程异常终止！")
        return

    # 2. isMessageExecuted 检查
    logger.info("检查消息是否已在目标链执行...")
    try:
        executed = getattr(manager.functions, methods["isMessageExecuted"])(digest_bytes32).call()
        logger.info(f"isMessageExecuted: {executed}")
        if executed:
            logger.info("跨链流程已完成，流程结束。")
            return
    except Exception as e:
        logger.error(f"调用isMessageExecuted失败: {e}")
        return

    # 3. getInboundQueuedTransfer 检查
    logger.info("检查消息是否在入站队列...")
    found_valid_queue = False
    for attempt in range(3):
        try:
            queued_info = getattr(manager.functions, methods["getInboundQueuedTransfer"])(digest_bytes32).call()
            # queued_info结构: (amount, txTimestamp, recipient)
            amount_queued = int(queued_info[0]) if len(queued_info) > 0 else 0
            tx_timestamp = int(queued_info[1]) if len(queued_info) > 1 else 0
            recipient = queued_info[2] if len(queued_info) > 2 else "0x0000000000000000000000000000000000000000"
            logger.info(f"getInboundQueuedTransfer返回: amount={amount_queued}, txTimestamp={tx_timestamp}, recipient={recipient}")
            # 判断是否全为0（空队列），否则为有效
            if amount_queued == 0 and tx_timestamp == 0 and (recipient.lower() == "0x0000000000000000000000000000000000000000" or int(recipient, 16) == 0):
                logger.warning("入站队列为空，10秒后重试({}/{})...".format(attempt+1, 3))
                sleep_with_log(10, logger)
            else:
                found_valid_queue = True
                break
        except Exception as e:
            logger.error(f"调用getInboundQueuedTransfer失败: {e}")
            sleep_with_log(10, logger)
    if not found_valid_queue:
        logger.error("未在入站队列找到有效消息，流程异常终止！")
        return
 
    # 4. getInboundLimitParams 检查
    logger.info("开始轮询入站速率限制参数...")
    while True:
        try:
            limit_info = getattr(manager.functions, methods["getInboundLimitParams"])(src_chain_id).call()
            # limit_info结构: (limit, currentCapacity, lastTxTimestamp)
            limit = Decimal(limit_info[0]) if len(limit_info) > 0 else Decimal(0)
            current_capacity = Decimal(limit_info[1]) if len(limit_info) > 1 else Decimal(0)
            last_tx_timestamp = int(limit_info[2]) if len(limit_info) > 2 else 0
            logger.info(f"当前入站额度: limit={limit}, currentCapacity={current_capacity}, lastTxTimestamp={last_tx_timestamp}，用户跨链数量: {amount}")
            # 只有limit和currentCapacity都大于等于amount时才进入下一步
            if limit >= amount and current_capacity >= amount:
                logger.info("额度充足，准备完成入站队列转账。")
                break
            else:
                logger.info("额度不足，30秒后重试...")
                sleep_with_log(30, logger)
        except Exception as e:
            logger.error(f"调用getInboundLimitParams失败: {e}")
            sleep_with_log(30, logger)

    # 5. completeInboundQueuedTransfer
    logger.info("调用completeInboundQueuedTransfer完成入站转账...")
    try:

        tx = getattr(manager.functions, methods["completeInboundQueuedTransfer"])(digest_bytes32).build_transaction({
            "from": from_address,
            "nonce": w3_dst.eth.get_transaction_count(from_address),
            "gas": 800000
        })
        tx = build_tx_with_gas_params(w3_dst, tx, logger)
        signed = w3_dst.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = w3_dst.eth.send_raw_transaction(signed.rawTransaction)
        logger.info(f"completeInboundQueuedTransfer已提交，tx_hash: {tx_hash.hex()}")
        receipt = w3_dst.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"completeInboundQueuedTransfer上链成功，区块号: {receipt.blockNumber}")
    except Exception as e:
        logger.error(f"completeInboundQueuedTransfer提交失败: {e}")
        return

    # 6. 再次检查isMessageExecuted
    try:
        executed = getattr(manager.functions, methods["isMessageExecuted"])(digest_bytes32).call()
        logger.info(f"最终isMessageExecuted: {executed}")
        if executed:
            logger.info("跨链流程已全部完成。")
        else:
            logger.warning("completeInboundQueuedTransfer后消息仍未执行，请人工检查。")
    except Exception as e:
        logger.error(f"最终isMessageExecuted查询失败: {e}")

# ========== 新增：处理VAA和claim的通用函数 ==========
def process_vaa_and_claim(config, logger, w3_src, w3_dst, account, private_key, 
                         src_tx_hash, min_unit_amount, transfer_params, dst, token):
    """
    处理VAA轮询、WebSocket监听、claim交易和结果确认的通用函数
    用于full_send和redeem_only模式
    """
    # 在循环之前预加载所有transceiver的ABI
    transceiver_abis = {}
    for transceiver_cfg in dst["transceivers"]:
        with open(transceiver_cfg["abi_path"], "r") as f:
            transceiver_abis[transceiver_cfg["name"]] = json.load(f)

    # 并发运行 VAA 轮询和 WebSocket 订阅（使用线程版本）
    logger.info("开始并发运行 VAA 轮询和 WebSocket 订阅...")
    
    # 创建并发管理器（线程版本）
    concurrent_manager = ConcurrentVAAPollerAndWatcher(
        config=config,
        logger=logger,
        src_tx_hash=src_tx_hash,
        min_unit_amount=min_unit_amount,
        recipient_on_dst=transfer_params["recipient"],
        wormhole_dst_chain_id=dst["wormhole_chain_id"],
        token=token
    )
    
    # 运行并发任务
    vaa, parsed_payload, is_received_dict, stop_event = concurrent_manager.run()
    
    if not vaa:
        logger.error("VAA获取或校验失败，流程终止。")
        return False
    
    # 立即判断状态并补发claim，不等待监听任务
    #logger.info("用他人交易测试，等待120秒让executor自动执行")
    #time.sleep(120)
    logger.info("VAA已获取，立即开始处理...")
    
    # 计算已收到的数量
    received_count = sum(1 for v in is_received_dict.values() if v)
    threshold = int(dst["threshold"])
    logger.info(f"目标链已发起claim交易的transceiver数量:: {received_count} / threshold={threshold}")
    
    if received_count >= threshold:
        logger.info("已达到threshold，目标链无需再发起claim交易，停止监听线程，进行结果确认...")
        # 停止监听线程（监听线程可能已自动停止，但这里确保一下）
        if stop_event:
            stop_event.set()
        
        # 进行结果确认
        digest = concurrent_manager.get_digest()
        if digest:
            confirm_result(config, w3_src, w3_dst, logger, digest)
        else:
            logger.error("无法获取digest，跳过结果确认。")
        return True
    
    # 获取未收到的transceiver
    transceivers = dst["transceivers"]
    unreceived = [t for t in transceivers if not is_received_dict.get(t["name"], False)]
    need_claim = threshold - received_count
    
    if need_claim > len(unreceived):
        logger.warning("未收到的transceiver数量不足以补齐threshold，全部补发")
        claim_list = unreceived
    else:
        claim_list = random.sample(unreceived, need_claim)
    logger.info(f"需补发claim的transceiver: {[t['name'] for t in claim_list]}")
    
    # 立即解码VAA并发送交易
    encodedVm_bytes = base64.b64decode(vaa)
    logger.info("VAA已完成Base64解码，准备构建交易")
    
    for transceiver_cfg in claim_list:
        # 从缓存中获取ABI，避免重复读取文件
        transceiver_abi = transceiver_abis[transceiver_cfg["name"]]
        transceiver = w3_dst.eth.contract(
            address=checksum(transceiver_cfg["address"]), 
            abi=transceiver_abi
        )
        method = getattr(transceiver.functions, transceiver_cfg["methods"]["receiveMessage"])
        nonce = w3_dst.eth.get_transaction_count(account.address)
        tx_dict = method(encodedVm_bytes).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 800000
        })
        tx_dict = build_tx_with_gas_params(w3_dst, tx_dict, logger)
        signed = w3_dst.eth.account.sign_transaction(tx_dict, private_key=private_key)
        tx_hash = w3_dst.eth.send_raw_transaction(signed.raw_transaction)
        logger.info(f"目标链 transceiver {transceiver_cfg['name']} claim交易已发送: {tx_hash.hex()}")
        
        # 等待交易上链
        receipt = w3_dst.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"目标链 transceiver {transceiver_cfg['name']} claim交易已上链，区块号: {receipt.blockNumber}")
    
    # 先等待3秒，让事件推送、状态同步完成（此时监听线程仍在运行）
    logger.info("等待3秒让状态更新&事件推送完成...")
    time.sleep(3)

    # 再停止WebSocket监听（此时事件已接收完毕，状态已更新）
    logger.info("所有claim交易已成功上链，停止WebSocket监听...")
    if stop_event:
        stop_event.set()

    # 最后读取最终状态（此时状态已同步完成）
    final_received_count = sum(1 for v in is_received_dict.values() if v)
    logger.info(f"最终状态: 目标链已发起claim交易的transceiver数量: {final_received_count} / threshold={threshold}")

    # 进行结果确认
    digest = concurrent_manager.get_digest()
    if digest:
        confirm_result(config, w3_src, w3_dst, logger, digest)
    else:
        logger.error("无法获取digest，跳过结果确认。")
    
    return True

# ========== 主流程 ==========

def main():
    """
    跨链主流程，包含配置加载、授权、发起跨链、拉取VAA、目标链赎回、状态确认等步骤
    """
    # 1. 加载配置和私钥
    config = load_config()
    load_dotenv()
    logger = setup_logger(config["logging"]["log_level"], config["logging"]["log_file"])
    logger.info("配置和日志系统加载完成。")

    mode = config["mode"]
    src = config["src"]
    dst = config["dst"]
    token = config["token"]
    transfer_params = config["transfer_params"]
    private_key = os.getenv(config["auth"]["private_key_env"])
    src_tx_hash = config.get("src_tx_hash", "")

    # 2. 初始化web3
    w3_src = init_web3(src["rpc"], enable_poa_middleware=src.get("is_poa", False))
    w3_dst = init_web3(dst["rpc"], enable_poa_middleware=dst.get("is_poa", False))
    account = w3_src.eth.account.from_key(private_key)
    logger.info(f"使用账户: {account.address}")

    erc20_abi = [
        {
            "constant": False,
            "inputs": [
                {"name": "_spender", "type": "address"},
                {"name": "_value", "type": "uint256"}
            ],
            "name": "approve",
            "outputs": [{"name": "", "type": "bool"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [{"name": "account", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "", "type": "uint256"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"}
            ],
            "name": "allowance",
            "outputs": [{"name": "", "type": "uint256"}],
            "type": "function"
        }
    ]
    erc20 = w3_src.eth.contract(address=checksum(token["address_on_src"]), abi=erc20_abi)
    min_unit_amount = amount_to_min_unit(transfer_params["amount"], token["decimals"])


# ========== full_send模式 ==========
    if mode == "full_send":
        # 3. 检查余额和授权
        balance = erc20.functions.balanceOf(account.address).call()
        human_balance = Decimal(balance) / Decimal(10 ** token["decimals"])
        logger.info(f"当前余额: {human_balance} {token['symbol']}")
        logger.info(f"跨链代币数量: {transfer_params['amount']} {token['symbol']}")
        if balance < min_unit_amount:
            logger.error("余额不足，无法跨链")
            sys.exit(1)

        # 检查授权（approve），如需则发起授权交易
        if token.get("approve_required", True) and mode == "full_send":
            allowance = erc20.functions.allowance(account.address, checksum(src["ntt_manager"]["address"])).call()
            if allowance < min_unit_amount:
                logger.info("开始授权 manager 合约...")
                approve_tx = erc20.functions.approve(checksum(src["ntt_manager"]["address"]), min_unit_amount)
                nonce = w3_src.eth.get_transaction_count(account.address)
                tx_dict = approve_tx.build_transaction({
                    "from": account.address,
                    "nonce": nonce,
                    "gas": 100000
                })
                tx_dict = build_tx_with_gas_params(w3_src, tx_dict, logger)
                signed = w3_src.eth.account.sign_transaction(tx_dict, private_key)
                tx_hash = w3_src.eth.send_raw_transaction(signed.raw_transaction)
                logger.info(f"授权交易已发送: {tx_hash.hex()}")
                w3_src.eth.wait_for_transaction_receipt(tx_hash)
                logger.info("授权完成")

        # 4. 发起跨链
        with open(src["ntt_manager"]["abi_path"], "r") as f:
            manager_abi = json.load(f)
        manager = w3_src.eth.contract(address=checksum(src["ntt_manager"]["address"]), abi=manager_abi)
        method = getattr(manager.functions, src["ntt_manager"]["method"])
        recipient_bytes32 = to_bytes32(transfer_params["recipient"])
        refund_address_bytes32 = to_bytes32(transfer_params["refund_address"])
        params = [           # 需要根据实际方法参数调整顺序
            min_unit_amount,
            transfer_params["recipient_wormhole_chain"],
            recipient_bytes32,
            refund_address_bytes32,
            transfer_params["should_queue"],
            Web3.to_bytes(hexstr=transfer_params["transceiver_instructions_hex"])
        ]
        recipient_chain = transfer_params["recipient_wormhole_chain"]
        instructions_bytes = Web3.to_bytes(
            hexstr=transfer_params["transceiver_instructions_hex"]
        )
        _, total_delivery_price = manager.functions.quoteDeliveryPrice(
            recipient_chain,
            instructions_bytes
        ).call()
        nonce = w3_src.eth.get_transaction_count(account.address)
        tx_dict = method(*params).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 500000,
            "value": total_delivery_price
        })
        tx_dict = build_tx_with_gas_params(w3_src, tx_dict, logger)
        signed = w3_src.eth.account.sign_transaction(tx_dict, private_key)
        tx_hash = w3_src.eth.send_raw_transaction(signed.raw_transaction)
        logger.info(f"跨链交易已发送: {tx_hash.hex()}")
        w3_src.eth.wait_for_transaction_receipt(tx_hash)
        logger.info("跨链交易已上链")
        src_tx_hash = tx_hash.hex()

        # 5. 调用通用函数处理VAA和claim
        process_vaa_and_claim(
            config=config,
            logger=logger,
            w3_src=w3_src,
            w3_dst=w3_dst,
            account=account,
            private_key=private_key,
            src_tx_hash=src_tx_hash,
            min_unit_amount=min_unit_amount,
            transfer_params=transfer_params,
            dst=dst,
            token=token
        )

    # ========== redeem_only模式 ==========
    elif mode == "redeem_only":
        # 调用通用函数处理VAA和claim
        process_vaa_and_claim(
            config=config,
            logger=logger,
            w3_src=w3_src,
            w3_dst=w3_dst,
            account=account,
            private_key=private_key,
            src_tx_hash=src_tx_hash,
            min_unit_amount=min_unit_amount,
            transfer_params=transfer_params,
            dst=dst,
            token=token
        )

# ========== complete_inbound模式 ==========
    elif mode == "complete_inbound":
        # 8. 结果确认
        digest = config.get("digest")
        if not digest:
            # 如果配置文件没有digest，则尝试用src_tx_hash获取
            if not src_tx_hash:
                logger.error("complete_inbound模式下digest和src_tx_hash均未配置，无法获取digest，流程终止。")
                return
            for attempt in range(3):
                digest = get_digest_from_src_tx(w3_src, src_tx_hash, logger)
                if digest:
                    break
                logger.warning(f"未获取到digest，10秒后重试({attempt+1}/3)...")
                sleep_with_log(10, logger)
            if not digest:
                logger.error("无法获取digest，流程终止。")
                return
        confirm_result(config, w3_src, w3_dst, logger, digest)

if __name__ == "__main__":
    main()
