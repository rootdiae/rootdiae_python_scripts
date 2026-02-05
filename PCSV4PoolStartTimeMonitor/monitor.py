import json
import logging
import time
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Tuple, Any
import os
import requests
from web3 import Web3
from web3.exceptions import ContractLogicError, BadFunctionCallOutput
from zoneinfo import ZoneInfo

# 飞书SDK导入
import lark_oapi as lark
from lark_oapi.api.bitable.v1 import *

# ============================ 1. 日志配置 (核心要求：控制台+文件输出，轮转) ============================
def setup_logger() -> logging.Logger:
    """配置日志系统，同时输出到控制台和文件，文件按大小轮转"""
    logger = logging.getLogger("BSC_Pool_Monitor")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # 避免重复输出

    # 格式配置
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 1.1 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 1.2 文件处理器（50MB/文件，保留5个备份）
    file_handler = RotatingFileHandler(
        "bsc_pool_monitor.log",
        maxBytes=50 * 1024 * 1024,  # 50MB
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger

# 初始化日志
logger = setup_logger()

# ============================ 2. 核心配置常量 (需用户替换钉钉Webhook) ============================
# 2.1 RPC配置（多节点轮询，无认证）
RPC_ENDPOINTS = [
    "https://bsc.drpc.org",
    "https://bsc-rpc.publicnode.com",
    "https://wallet.okex.org/fullnode/bsc/discover/rpc"
]
RPC_TIMEOUT = 10  # 单次请求超时时间（秒）
RPC_RETRY_TIMES = 5  # 重试次数

# 2.2 钉钉配置（硬编码，无加签，需替换为实际Webhook）
DINGTALK_WEBHOOK = "https://oapi.dingtalk.com/robot/send?access_token=6d5f360d99ba46a2552bc0c8338fb8cecc332d22a28b9c47a3805c99a49d9d79"
DINGTALK_TIMEOUT = 5  # 钉钉请求超时（秒）
DINGTALK_RETRY_TIMES = 3  # 钉钉重试次数

# 2.3 合约与事件配置
# PoolStartedAtUpdated事件相关
EVENT_ADDRESS = Web3.to_checksum_address("0x72e09eBd9b24F47730b651889a4eD984CBa53d90").lower()
EVENT_TOPIC0 = "0xcaccc4bc886d75b13de806bf4292e4cc78a042eae40849e6a96242f7d03cb5fb".lower()
EVENT_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "PoolId", "name": "poolId", "type": "bytes32"},
            {"indexed": False, "internalType": "uint256", "name": "startedTimestamp", "type": "uint256"},
            {"indexed": False, "internalType": "address", "name": "operator", "type": "address"}
        ],
        "name": "PoolStartedAtUpdated",
        "type": "event"
    }
]

# poolIdToPoolKey合约1
POOL_KEY_CONTRACT1 = Web3.to_checksum_address("0xa0FfB9c1CE1Fe56963B0321B32E7A0302114058b").lower()
# poolIdToPoolKey合约2
POOL_KEY_CONTRACT2 = Web3.to_checksum_address("0xc697d2898e0d09264376196696c51d7abbbaa4a9").lower()
# poolIdToPoolKey方法ABI
POOL_KEY_ABI = [
    {
        "inputs": [{"internalType": "PoolId", "name": "id", "type": "bytes32"}],
        "name": "poolIdToPoolKey",
        "outputs": [
            {"internalType": "Currency", "name": "currency0", "type": "address"},
            {"internalType": "Currency", "name": "currency1", "type": "address"},
            {"internalType": "contract IHooks", "name": "hooks", "type": "address"},
            {"internalType": "contract IPoolManager", "name": "poolManager", "type": "address"},
            {"internalType": "uint24", "name": "fee", "type": "uint24"},
            {"internalType": "bytes32", "name": "parameters", "type": "bytes32"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# ERC20 symbol方法ABI
ERC20_SYMBOL_ABI = [
    {
        "inputs": [],
        "name": "symbol",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    }
]

# 2.4 飞书配置
FEISHU_APP_ID = " "  # 飞书应用凭证APP_ID
FEISHU_APP_SECRET = " "  # 飞书应用凭证APP_SECRET
FEISHU_APP_TOKEN = " " # 飞书多维表格
FEISHU_TABLE_ID = " "  # 飞书多维表格ID
FEISHU_RETRY_TIMES = 3  # 飞书表格更新请求重试次数

# 2.5 文件路径配置
PROCESSED_BLOCK_FILE = "processed_block.json"
POOL_MAPPING_FILE = "pool_mapping.json"  # 新增：本地映射表文件
PENDING_POOLS_FILE = "pending_pools.json"

# 2.6 时区配置
BEIJING_TZ = ZoneInfo("Asia/Shanghai")
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000".lower()

# ============================ 3. 工具函数 (通用工具，时间/文件/RPC/合约) ============================
def get_beijing_time(timestamp: Optional[int] = None) -> datetime:
    """
    获取当前北京时间，或转换时间戳为北京时间
    :param timestamp: 可选，UTC时间戳（秒）
    :return: 北京时间datetime对象
    """
    if timestamp is None:
        return datetime.now(BEIJING_TZ)
    return datetime.fromtimestamp(timestamp, tz=BEIJING_TZ)

def format_beijing_time(dt: datetime) -> str:
    """格式化北京时间为指定格式：YYYY年MM月DD日HH:MM(北京时间）"""
    return dt.strftime("%Y年%m月%d日%H:%M(北京时间）")

def format_timestamp_to_beijing(timestamp: int) -> str:
    """将UTC时间戳转换为格式化的北京时间字符串"""
    return format_beijing_time(get_beijing_time(timestamp))

def normalize_address(address: str) -> str:
    """标准化地址：小写，去除首尾空格"""
    return address.strip().lower()

def normalize_topic(topic: str) -> str:
    """标准化topic：小写，去除首尾空格"""
    return topic.strip().lower()

def load_json_file(file_path: str, default: Any = None) -> Any:
    """
    加载JSON文件，文件不存在/解析失败时返回默认值
    :param file_path: 文件路径
    :param default: 默认返回值
    :return: 解析后的JSON数据
    """
    if default is None:
        default = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.info(f"文件 {file_path} 不存在，使用默认值: {default}")
        return default
    except json.JSONDecodeError:
        logger.error(f"文件 {file_path} 解析失败，使用默认值: {default}")
        return default
    except Exception as e:
        logger.error(f"读取文件 {file_path} 异常: {str(e)}", exc_info=True)
        return default

def save_json_file(file_path: str, data: Any) -> bool:
    """
    保存JSON文件，失败时重试3次
    :param file_path: 文件路径
    :param data: 要保存的数据
    :return: 是否成功
    """
    retry_times = 3
    for i in range(retry_times):
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.warning(f"保存文件 {file_path} 失败（第{i+1}次重试）: {str(e)}")
            time.sleep(1)
    logger.error(f"保存文件 {file_path} 失败，已重试{retry_times}次")
    return False

def rpc_request(method: str, params: List[Any], endpoint_idx: int = 0) -> Optional[Dict]:
    """
    多节点轮询的RPC请求，自动重试
    :param method: RPC方法名
    :param params: RPC参数列表
    :param endpoint_idx: 当前使用的节点索引
    :return: RPC响应结果（result字段），失败返回None
    """
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": int(time.time() * 1000)  # 唯一ID
    }

    for retry in range(RPC_RETRY_TIMES):
        # 切换节点（轮询）
        current_endpoint = RPC_ENDPOINTS[(endpoint_idx + retry) % len(RPC_ENDPOINTS)]
        try:
            response = requests.post(
                current_endpoint,
                json=payload,
                timeout=RPC_TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()  # 触发HTTP错误
            result = response.json()
            logger.info(f"RPC请求成功: {method} | 节点: {current_endpoint} | 响应: {json.dumps(result)}")
            
            if "error" in result:
                logger.error(f"RPC返回错误: {result['error']} | 节点: {current_endpoint}")
                continue
            return result.get("result")
        except requests.exceptions.RequestException as e:
            logger.warning(f"RPC请求失败（第{retry+1}次）: {current_endpoint} | 错误: {str(e)}")
            continue
        except Exception as e:
            logger.error(f"RPC请求异常（第{retry+1}次）: {current_endpoint} | 错误: {str(e)}", exc_info=True)
            continue

    logger.error(f"RPC请求 {method} 失败，已重试{RPC_RETRY_TIMES}次，所有节点均不可用")
    return None

def get_latest_block_number() -> Optional[int]:
    """获取BSC最新区块号（十进制）"""
    result = rpc_request("eth_blockNumber", [])
    if result is None:
        return None
    try:
        return int(result, 16)
    except ValueError:
        logger.error(f"解析最新区块号失败: {result}")
        return None

def call_contract_method(
    contract_address: str,
    abi: List[Dict],
    method_name: str,
    args: List[Any],
    block_identifier: str = "latest"
) -> Optional[Any]:
    """
    调用合约只读方法（优化版：使用Web3.py原生call方式 + 多节点轮询重试，避免手动解码错误）
    :param contract_address: 合约地址
    :param abi: 合约ABI
    :param method_name: 方法名
    :param args: 方法参数
    :param block_identifier: 区块标识符（latest/pending等）
    :return: 方法返回值，失败返回None
    """
    # 遍历RPC节点轮询，失败则切换节点重试
    for retry in range(RPC_RETRY_TIMES):
        # 选择当前重试轮次对应的节点（轮询）
        endpoint_idx = retry % len(RPC_ENDPOINTS)
        current_endpoint = RPC_ENDPOINTS[endpoint_idx]
        
        try:
            # 初始化当前节点的Web3实例（每次重试切换节点）
            w3 = Web3(Web3.HTTPProvider(current_endpoint, request_kwargs={"timeout": RPC_TIMEOUT}))
            if not w3.is_connected():
                logger.warning(f"节点 {current_endpoint} 连接失败，切换下一个节点（第{retry+1}次重试）")
                continue
            
            # 创建合约实例（简洁方式，无需手动编码）
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(contract_address),
                abi=abi
            )
            
            # 核心优化：使用Web3.py原生的functions.call()方式（自动编码/解码，无版本兼容问题）
            func = contract.functions[method_name](*args)
            result = func.call(block_identifier=block_identifier)
            
            logger.info(f"合约调用成功 | 节点: {current_endpoint} | 合约: {contract_address}.{method_name} | 返回值: {result}")
            return result
        
        # 捕获合约逻辑错误（如方法不存在、参数错误）
        except (ContractLogicError, BadFunctionCallOutput) as e:
            logger.warning(f"合约 {contract_address}.{method_name} 逻辑错误（节点：{current_endpoint}）: {str(e)}")
            break  # 逻辑错误无需重试其他节点
        
        # 捕获节点连接/请求超时错误
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            logger.warning(f"节点 {current_endpoint} 请求失败（第{retry+1}次重试）: {str(e)}")
            continue
        
        # 捕获其他异常
        except Exception as e:
            logger.error(f"调用合约 {contract_address}.{method_name} 异常（节点：{current_endpoint}）: {str(e)}", exc_info=True)
            continue
    
    # 所有节点/重试均失败
    logger.error(f"合约调用失败 | 合约: {contract_address}.{method_name} | 已重试{RPC_RETRY_TIMES}次，所有节点均不可用")
    return None

def get_token_symbol(token_address: str) -> str:
    """
    获取代币符号，处理特殊场景
    :param token_address: 代币地址
    :return: 代币符号（大写），失败返回"未知代币"
    """
    token_address = normalize_address(token_address)
    
    # 零地址返回BNB
    if token_address == ZERO_ADDRESS:
        return "BNB"
    
    # 调用symbol方法
    try:
        result = call_contract_method(token_address, ERC20_SYMBOL_ABI, "symbol", [])
        if result is None:  # 直接判断result是否为空（不再判断len(result)）
            logger.warning(f"代币 {token_address} symbol方法返回空")
            return "未知代币"

        symbol = str(result).strip().upper()  # 统一大写
        logger.info(f"获取代币 {token_address} symbol成功: {symbol}")  # 新增日志，便于验证
        return symbol if symbol else "未知代币"
    except (ContractLogicError, BadFunctionCallOutput):
        logger.warning(f"代币 {token_address} 调用symbol方法失败（合约逻辑错误）")
        return "未知代币"
    except Exception as e:
        logger.error(f"获取代币 {token_address} symbol失败: {str(e)}", exc_info=True)
        return "未知代币"

# ============================ 3.5 飞书API客户端模块 ============================
# 全局飞书客户端实例
feishu_client = None

def init_feishu_client():
    """初始化飞书客户端"""
    global feishu_client
    if feishu_client is None:
        feishu_client = lark.Client.builder() \
            .app_id(FEISHU_APP_ID) \
            .app_secret(FEISHU_APP_SECRET) \
            .log_level(lark.LogLevel.DEBUG) \
            .build()
    return feishu_client

def create_feishu_records(records_data):
    """批量创建飞书表格记录"""
    client = init_feishu_client()
    
    for retry in range(FEISHU_RETRY_TIMES):
        try:
            request: BatchCreateAppTableRecordRequest = BatchCreateAppTableRecordRequest.builder() \
                .app_token(FEISHU_APP_TOKEN) \
                .table_id(FEISHU_TABLE_ID) \
                .request_body(BatchCreateAppTableRecordRequestBody.builder()
                    .records(records_data)
                    .build()) \
                .build()
    
            response: BatchCreateAppTableRecordResponse = client.bitable.v1.app_table_record.batch_create(request)
    
            if response.success():
                logger.info(f"飞书记录创建成功")
                return response.data.records
            else:
                logger.warning(f"飞书记录创建失败（第{retry+1}次）: {response.msg}")
        except Exception as e:
            logger.warning(f"飞书API调用异常（第{retry+1}次）: {str(e)}")
        time.sleep(1)
    
    logger.error(f"飞书记录创建失败，已重试{FEISHU_RETRY_TIMES}次")
    return None

def update_feishu_records(records_data):
    """批量更新飞书表格记录"""
    client = init_feishu_client()
    
    for retry in range(FEISHU_RETRY_TIMES):
        try:
            request: BatchUpdateAppTableRecordRequest = BatchUpdateAppTableRecordRequest.builder() \
                .app_token(FEISHU_APP_TOKEN) \
                .table_id(FEISHU_TABLE_ID) \
                .request_body(BatchUpdateAppTableRecordRequestBody.builder()
                    .records(records_data)
                    .build()) \
                .build()
    
            response: BatchUpdateAppTableRecordResponse = client.bitable.v1.app_table_record.batch_update(request)
    
            if response.success():
                logger.info(f"飞书记录更新成功")
                return True
            else:
                logger.warning(f"飞书记录更新失败（第{retry+1}次）: {response.msg}")
        except Exception as e:
            logger.warning(f"飞书API调用异常（第{retry+1}次）: {str(e)}")
        time.sleep(1)
    
    logger.error(f"飞书记录更新失败，已重试{FEISHU_RETRY_TIMES}次")
    return False

# ============================ 3.6 本地映射表模块 ============================
def load_pool_mapping() -> Dict:
    """加载本地映射表"""
    return load_json_file(POOL_MAPPING_FILE, {})

def save_pool_mapping(mapping: Dict):
    """保存本地映射表"""
    save_json_file(POOL_MAPPING_FILE, mapping)

def get_mapping_record(poolid: str) -> Optional[Dict]:
    """获取指定poolid的映射记录"""
    mapping = load_pool_mapping()
    return mapping.get(poolid)

def update_mapping_record(poolid: str, record_id: str, event_block: int):
    """更新映射表记录"""
    mapping = load_pool_mapping()
    mapping[poolid] = {
        "record_id": record_id,
        "event_block": event_block
    }
    save_pool_mapping(mapping)

# ============================ 4. 钉钉通知模块 ============================
def send_dingtalk_notification(title: str, content: str) -> bool:
    """
    发送钉钉Markdown通知，失败重试
    :param title: 通知标题
    :param content: Markdown格式内容
    :return: 是否成功
    """
    payload = {
        "msgtype": "markdown",
        "markdown": {
            "title": title,
            "text": content
        }
    }

    for retry in range(DINGTALK_RETRY_TIMES):
        try:
            response = requests.post(
                DINGTALK_WEBHOOK,
                json=payload,
                timeout=DINGTALK_TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            result = response.json()
            if result.get("errcode") == 0:
                logger.info(f"钉钉通知发送成功: {title}")
                return True
            else:
                logger.warning(f"钉钉通知返回错误（第{retry+1}次）: {result}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"钉钉通知发送失败（第{retry+1}次）: {str(e)}")
        time.sleep(1)
    
    logger.error(f"钉钉通知发送失败，已重试{DINGTALK_RETRY_TIMES}次: {title}")
    return False

def send_event_parse_failure_notification(tx_hash: str, error_msg: str):
    """发送事件解析失败的钉钉通知"""
    current_time = format_beijing_time(get_beijing_time())
    content = f"""# PoolStartedAtUpdated事件解析失败
- 交易哈希：[点击查看](https://bscscan.com/tx/{tx_hash})
- 失败原因：{error_msg}
- 失败时间：{current_time}
"""
    send_dingtalk_notification("PoolStartedAtUpdated事件解析失败", content)

def send_event_notification(tx_hash: str, pool_id: str, started_time: str):
    """发送新事件的钉钉通知"""
    content = f"""# PoolStartedAtUpdated新事件通知
- 交易哈希：[点击查看](https://bscscan.com/tx/{tx_hash})
- poolid：{pool_id}
- startedTimestamp：{started_time}
"""
    send_dingtalk_notification("PoolStartedAtUpdated新事件通知", content)

def send_pool_info_notification(
    pool_id: str,
    currency0_symbol: str,
    currency1_symbol: str,
    started_time: str,
    currency0_address: str,
    currency1_address: str,
    tx_hash: str
):
    """发送池子信息的钉钉通知"""
    title = f"{currency0_symbol}/{currency1_symbol}新池子{started_time.split('(')[0]}开始交易"
    content = f"""# {title}
- poolid: [池子链接](https://pancakeswap.finance/liquidity/pool/bsc/{pool_id})
- 代币0：[{currency0_symbol}](https://bscscan.com/address/{currency0_address})
- 代币1：[{currency1_symbol}](https://bscscan.com/address/{currency1_address})
- 开始交易时间：{started_time}
- 交易哈希：[点击查看](https://bscscan.com/tx/{tx_hash})
"""
    send_dingtalk_notification(title, content)

# ============================ 5. 事件查询模块 ============================
def load_processed_block() -> int:
    """
    加载最后处理的区块号
    - 若文件不存在：fromBlock = 最新区块 - 5000（最小为0），并初始化文件
    - 若文件存在：加载文件中的last_processed_block（默认0）
    :return: 处理起始区块号
    """
    # 先检查文件是否存在
    if not os.path.exists(PROCESSED_BLOCK_FILE):
        logger.info(f"processed_block.json 文件不存在，初始化起始区块为最新区块-5000")
        # 获取最新区块号
        latest_block = get_latest_block_number()
        if latest_block is None:
            logger.warning("获取最新区块号失败，起始区块默认设为0")
            init_block = 0
        else:
            # 计算起始区块（最小为0）
            init_block = max(latest_block - 5000, 0)
            logger.info(f"最新区块号: {latest_block}，初始化起始区块: {init_block}")
        
        # 初始化并保存文件
        save_processed_block(init_block)
        return init_block
    else:
        # 文件存在，加载原有逻辑
        data = load_json_file(PROCESSED_BLOCK_FILE, {"last_processed_block": 0})
        return int(data.get("last_processed_block", 0))

def save_processed_block(block_number: int):
    """保存最后处理的区块号"""
    data = {
        "last_processed_block": block_number,
        "last_update_time": get_beijing_time().isoformat()
    }
    save_json_file(PROCESSED_BLOCK_FILE, data)

def parse_pool_event(log: Dict) -> Optional[Dict]:
    """
    解析单个PoolStartedAtUpdated事件日志
    :param log: eth_getLogs返回的日志项
    :return: 解析后的事件数据，失败返回None
    """
    try:
        # 基础校验
        tx_hash = log.get("transactionHash", "").strip().lower()
        if not tx_hash:
            raise ValueError("交易哈希为空")
        
        # 解析topics（topic0=事件签名，topic1=poolId）
        topics = log.get("topics", [])
        if len(topics) < 2:
            raise ValueError(f"topics长度不足，预期至少2，实际{len(topics)}")
        
        pool_id = normalize_topic(topics[1])
        if not pool_id.startswith("0x"):
            raise ValueError(f"poolId格式错误: {pool_id}")
        
        # 解析data字段（startedTimestamp + operator）
        w3 = Web3()
        event_abi = EVENT_ABI[0]
        # 解码data字段
        decoded_data = w3.codec.decode(
            [inp["type"] for inp in event_abi["inputs"] if not inp["indexed"]],
            bytes.fromhex(log.get("data", "0x")[2:])
        )
        if len(decoded_data) < 1:
            raise ValueError("data字段解码后无数据")
        
        started_timestamp = int(decoded_data[0])  # uint256时间戳（UTC）
        if started_timestamp <= 0:
            raise ValueError(f"startedTimestamp无效: {started_timestamp}")
        
        # 构建返回数据
        return {
            "poolid": pool_id,
            "hash": tx_hash,
            "startedTimestamp": started_timestamp,
            "startedTimeStr": format_timestamp_to_beijing(started_timestamp),
            "eventBlock": int(log.get("blockNumber", "0x0"), 16),
            "eventTime": get_beijing_time().isoformat()
        }
    except Exception as e:
        error_msg = str(e)
        tx_hash = log.get("transactionHash", "未知")
        logger.error(f"解析事件失败 | 交易哈希: {tx_hash} | 错误: {error_msg}", exc_info=True)
        # 发送解析失败钉钉通知
        send_event_parse_failure_notification(tx_hash, error_msg)
        return None

def query_pool_events() -> List[Dict]:
    """
    查询指定区块范围的PoolStartedAtUpdated事件
    :return: 解析后的事件列表（去重，保留最晚的startedTimestamp）
    """
    # 1. 获取区块范围
    from_block = load_processed_block()
    to_block = get_latest_block_number()
    
    if to_block is None or from_block >= to_block:
        logger.info(f"无新区块可查询 | from_block: {from_block} | to_block: {to_block}")
        return []
    
    logger.info(f"开始查询事件 | from_block: {from_block} | to_block: {to_block}")
    
    # 2. 构建eth_getLogs参数
    params = [
        {
            "address": EVENT_ADDRESS,
            "topics": [EVENT_TOPIC0],
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block)
        }
    ]
    
    # 3. 调用RPC
    logs = rpc_request("eth_getLogs", params)
    if not logs:
        logger.error("eth_getLogs返回空")
        # 即使返回空，也要更新已处理区块
        save_processed_block(to_block)        
        return []
    
    # 4. 解析日志并去重（同一poolId保留区块号最大的）
    parsed_events = {}
    for log in logs:
        event = parse_pool_event(log)
        if not event:
            continue
        
        pool_id = event["poolid"]
        # 保留区块号更大的事件（即最晚的）
        if pool_id not in parsed_events or event["eventBlock"] > parsed_events[pool_id]["eventBlock"]:
            parsed_events[pool_id] = event
    
    # 5. 更新已处理区块
    save_processed_block(to_block)
    
    # 6. 转换为列表返回
    result = list(parsed_events.values())
    logger.info(f"事件查询完成 | 解析出{len(result)}个唯一事件")
    return result

def process_new_events(events: List[Dict]):
    """处理新查询到的事件，保存到飞书表格"""
    if not events:
        return
    
    # 加载本地映射表
    mapping = load_pool_mapping()
    
    # 分新增和更新两类处理
    create_records = []
    update_records = []
    
    for event in events:
        poolid = event["poolid"]
        event_block = event["eventBlock"]
        
        # 构建飞书记录字段
        fields = {
            "poolid": {
                "text": poolid,
                "link": f"https://pancakeswap.finance/liquidity/pool/bsc/{poolid}"
            },
            "hash": {
                "text": event["hash"],
                "link": f"https://bscscan.com/tx/{event['hash']}"
            },
            # 转换为毫秒级UTC时间戳
            "startTimestamp": event["startedTimestamp"] * 1000,
            "currency0_address": "",
            "currency0_symbol": "",
            "currency1_address": "",
            "currency1_symbol": "",
            "remark": ""
        }
        
        # 检查映射表，确定操作类型
        if poolid in mapping:
            # 已存在记录，检查block号
            existing_record = mapping[poolid]
            if event_block > existing_record["event_block"]:
                # block号更大，需要更新
                # 构建更新字段，包含hash和startTimestamp
                update_fields = {
                    "hash": {
                        "text": event["hash"],
                        "link": f"https://bscscan.com/tx/{event['hash']}"
                    },
                    # 转换为毫秒级UTC时间戳
                    "startTimestamp": event["startedTimestamp"] * 1000,
                    "currency0_address": "",
                    "currency0_symbol": "",
                    "currency1_address": "",
                    "currency1_symbol": "",
                    "remark": ""
                }
                update_records.append(AppTableRecord.builder()
                    .fields(update_fields)
                    .record_id(existing_record["record_id"])
                    .build())
        else:
            # 新记录，需要新增
            create_records.append(AppTableRecord.builder()
                .fields(fields)
                .build())
    
    # 处理新增记录
    if create_records:
        logger.info(f"开始创建{len(create_records)}条飞书记录")
        created_records = create_feishu_records(create_records)
        if created_records:
            # 更新映射表
            for i, created in enumerate(created_records):
                if i < len(events):
                    event = events[i]  # 假设顺序一致
                    update_mapping_record(
                        event["poolid"],
                        created.record_id,
                        event["eventBlock"]
                    )
    
    # 处理更新记录
    if update_records:
        logger.info(f"开始更新{len(update_records)}条飞书记录")
        update_feishu_records(update_records)
        # 更新映射表中的block号 - 使用事件池直接映射，确保准确性
        for event in events:
            poolid = event["poolid"]
            if poolid in mapping:
                # 更新映射表中的最新block号
                update_mapping_record(
                    poolid,
                    mapping[poolid]["record_id"],
                    event["eventBlock"]
                )
    
    # 更新待查询池子列表
    update_pending_pools(events)

def update_pending_pools(events: List[Dict]):
    """更新待查询池子列表"""
    # 加载现有待查询列表
    pending_pools = load_json_file(PENDING_POOLS_FILE, [])
    pending_dict = {item["poolid"]: item for item in pending_pools}
    
    # 新增/更新待查询池子
    current_time = int(get_beijing_time().timestamp())
    for event in events:
        pool_id = event["poolid"]
        pending_dict[pool_id] = {
            "poolid": pool_id,
            "startedTimestamp": event["startedTimestamp"],  # UTC时间戳
            "detect_time": current_time,  # 事件检测时间（北京时间戳）
            "last_query_time": 0,
            "query_count": 0
        }
    
    # 保存
    save_json_file(PENDING_POOLS_FILE, list(pending_dict.values()))

# ============================ 6. 池子查询模块 ============================
def load_pending_pools() -> List[Dict]:
    """加载待查询池子列表"""
    return load_json_file(PENDING_POOLS_FILE, [])

def save_pending_pools(pools: List[Dict]):
    """保存待查询池子列表"""
    save_json_file(PENDING_POOLS_FILE, pools)

def query_pool_key(pool_id: str) -> Optional[Tuple[str, str]]:
    """
    查询池子的currency0和currency1地址
    :param pool_id: 池子ID
    :return: (currency0, currency1)，失败返回None
    """
    # 先查合约1
    result = call_contract_method(POOL_KEY_CONTRACT1, POOL_KEY_ABI, "poolIdToPoolKey", [pool_id])
    if result and len(result) >= 2:
        currency0 = normalize_address(result[0])
        currency1 = normalize_address(result[1])
        # 若不全为零地址，直接返回
        if currency0 != ZERO_ADDRESS or currency1 != ZERO_ADDRESS:
            return (currency0, currency1)
    
    # 合约1返回全零，查合约2
    result = call_contract_method(POOL_KEY_CONTRACT2, POOL_KEY_ABI, "poolIdToPoolKey", [pool_id])
    if result and len(result) >= 2:
        currency0 = normalize_address(result[0])
        currency1 = normalize_address(result[1])
        return (currency0, currency1)
    
    logger.warning(f"池子 {pool_id} 查询poolIdToPoolKey返回全零地址")
    return None

def process_single_pool(pool: Dict) -> Optional[Dict]:
    """
    处理单个池子查询
    :param pool: 待查询池子信息
    :return: 成功返回更新后的池子数据，失败返回None
    """
    pool_id = pool["poolid"]
    started_ts = pool["startedTimestamp"]  # UTC时间戳
    current_time = get_beijing_time()
    started_time = get_beijing_time(started_ts)  # 转换为北京时间
    
    logger.info(f"开始查询池子信息 | poolId: {pool_id} | 开盘时间: {format_beijing_time(started_time)}")
    
    # 查询池子key
    pool_key = query_pool_key(pool_id)
    if not pool_key or (pool_key[0] == ZERO_ADDRESS and pool_key[1] == ZERO_ADDRESS):
        logger.warning(f"池子 {pool_id} 未查询到有效代币地址")
        return None
    
    # 获取代币符号
    currency0_addr, currency1_addr = pool_key
    currency0_symbol = get_token_symbol(currency0_addr)
    currency1_symbol = get_token_symbol(currency1_addr)
    
    # 从映射表获取飞书record_id
    mapping_record = get_mapping_record(pool_id)
    if not mapping_record:
        logger.error(f"池子 {pool_id} 未在映射表中找到对应记录")
        return None
    
    # 构建更新字段
    update_fields = {
        "currency0_address": currency0_addr,
        "currency0_symbol": currency0_symbol,
        "currency1_address": currency1_addr,
        "currency1_symbol": currency1_symbol,
        "remark": ""
    }
    
    # 调用飞书API更新记录
    update_records = [AppTableRecord.builder()
        .fields(update_fields)
        .record_id(mapping_record["record_id"])
        .build()]
    
    if update_feishu_records(update_records):
        logger.info(f"池子 {pool_id} 信息更新完成")
        # 发送池子通知
        send_pool_info_notification(
            pool_id=pool_id,
            currency0_symbol=currency0_symbol,
            currency1_symbol=currency1_symbol,
            started_time=format_beijing_time(started_time),
            currency0_address=currency0_addr,
            currency1_address=currency1_addr,
            tx_hash=""
        )
        return pool
    else:
        logger.error(f"池子 {pool_id} 信息更新失败")
        return None

def check_pool_query_time(pool: Dict) -> bool:
    """
    检查是否到达池子查询时间
    :param pool: 待查询池子信息
    :return: 是否需要查询
    """
    current_time = get_beijing_time()
    started_ts = pool["startedTimestamp"]
    started_time = get_beijing_time(started_ts)
    detect_time = get_beijing_time(pool["detect_time"])
    last_query_time = pool["last_query_time"]
    
    # 转换为时间戳（北京时间）
    current_ts = int(current_time.timestamp())
    started_ts_cn = int(started_time.timestamp())
    two_hours_before_started = started_ts_cn - 2 * 3600  # 开盘前2小时
    
    # 已过开盘时间：仅首次查询
    if current_ts > started_ts_cn:
        if last_query_time == 0:
            logger.info(f"池子 {pool['poolid']} 已过开盘时间，执行首次查询")
            return True
        else:
            # 更新飞书记录的remark
            pool_id = pool["poolid"]
            mapping_record = get_mapping_record(pool_id)
            if mapping_record:
                update_fields = {
                    "remark": "已过PoolStartedAtUpdated事件设定的开盘时间，不再发起池子信息查询"
                }
                update_records = [AppTableRecord.builder()
                    .fields(update_fields)
                    .record_id(mapping_record["record_id"])
                    .build()]
                update_feishu_records(update_records)
            logger.info(f"池子 {pool['poolid']} 已过开盘时间，不再查询")
            return False
    
    # 开盘前2小时前：整点查询
    if current_ts < two_hours_before_started:
        # 整点且未在当前小时查询过
        if current_time.minute == 0 and (last_query_time == 0 or not datetime.fromtimestamp(last_query_time, BEIJING_TZ).hour == current_time.hour):
            logger.info(f"池子 {pool['poolid']} 开盘前2小时前，整点查询")
            return True
        return False
    
    # 开盘前2小时内：每10分钟查询
    if current_time.minute % 10 == 0 and (last_query_time == 0 or not datetime.fromtimestamp(last_query_time, BEIJING_TZ).minute == current_time.minute):
        logger.info(f"池子 {pool['poolid']} 开盘前2小时内，每10分钟查询")
        return True
    
    return False

def run_pool_query():
    """执行池子查询逻辑"""
    pending_pools = load_pending_pools()
    if not pending_pools:
        logger.info("无待查询池子")
        return
    
    updated_pending = []
    current_ts = int(get_beijing_time().timestamp())
    
    for pool in pending_pools:
        # 检查是否需要查询
        if check_pool_query_time(pool):
            # 执行查询
            result = process_single_pool(pool)
            if result:
                # 查询成功，移出待查询列表
                logger.info(f"池子 {pool['poolid']} 查询成功，移出待查询列表")
                continue
            else:
                # 查询失败，更新最后查询时间
                pool["last_query_time"] = current_ts
                pool["query_count"] += 1
        
        # 检查是否已过开盘时间（需要移出）
        started_time = get_beijing_time(pool["startedTimestamp"])
        if current_ts > int(started_time.timestamp()) and pool["last_query_time"] > 0:
            # 更新飞书记录的remark
            pool_id = pool["poolid"]
            mapping_record = get_mapping_record(pool_id)
            if mapping_record:
                update_fields = {
                    "remark": "已过PoolStartedAtUpdated事件设定的开盘时间，不再发起池子信息查询"
                }
                update_records = [AppTableRecord.builder()
                    .fields(update_fields)
                    .record_id(mapping_record["record_id"])
                    .build()]
                update_feishu_records(update_records)
            logger.info(f"池子 {pool['poolid']} 已过开盘时间且查询过，移出待查询列表")
            continue
        
        # 保留到待查询列表
        updated_pending.append(pool)
    
    # 保存更新后的待查询列表
    save_pending_pools(updated_pending)
    logger.info(f"池子查询完成 | 剩余待查询池子: {len(updated_pending)}")

# ============================ 7. 主循环模块 ============================
def main():
    """主循环：常驻运行，定时执行事件查询和池子查询"""
    logger.info("=== BSC PoolStartedAtUpdated 监控程序启动 ===")
    
    # 程序启动时发送钉钉通知
    send_dingtalk_notification("PoolStartedAtUpdated新事件监控重启", "PoolStartedAtUpdated新事件监控重启")
   
    # ========== 核心文件初始化 ==========
    # 1. 初始化 processed_block.json（已在load_processed_block中处理，此处仅确保文件存在）
    if not os.path.exists(PROCESSED_BLOCK_FILE):
        load_processed_block()  # 自动初始化文件
    
    # 2. 初始化 pool_mapping.json（不存在则新建空文件）
    if not os.path.exists(POOL_MAPPING_FILE):
        logger.info(f"{POOL_MAPPING_FILE} 文件不存在，自动新建空文件")
        save_json_file(POOL_MAPPING_FILE, {})
    
    # 3. 初始化 pending_pools.json（不存在则新建空数组）
    if not os.path.exists(PENDING_POOLS_FILE):
        logger.info(f"{PENDING_POOLS_FILE} 文件不存在，自动新建空文件")
        save_json_file(PENDING_POOLS_FILE, [])
    
    # 4. 初始化飞书客户端
    init_feishu_client()
    # ========== 初始化结束 ==========

    # ========== 新增：初次启动时立即执行一次事件查询 ==========
    logger.info("=== 程序初次启动，立即执行一次事件查询 ===")
    events = query_pool_events()
    if events:
        # 发送事件通知
        for event in events:
            send_event_notification(
                tx_hash=event["hash"],
                pool_id=event["poolid"],
                started_time=event["startedTimeStr"]
            )
        # 更新飞书表格
        process_new_events(events)
        update_pending_pools(events)
    # 2. 初次启动立即执行池子查询（核心新增）
    logger.info("=== 程序初次启动，立即执行一次池子查询 ===")
    run_pool_query()
    # ========== 初次查询结束 ==========

    # 初始化标记（避免同一分钟重复触发）
    event_query_triggered = False
    hourly_pool_query_triggered = False
    ten_min_pool_query_triggered = False
    
    while True:
        try:
            current_time = get_beijing_time()
            current_minute = current_time.minute
            
            # 1. 每30分钟执行事件查询（0分/30分）
            if current_minute in [0, 30] and not event_query_triggered:                
                logger.info("=== 触发定时事件查询 ===")
                # 查询事件
                events = query_pool_events()
                if events:
                    # 发送事件通知
                    for event in events:
                        send_event_notification(
                            tx_hash=event["hash"],
                            pool_id=event["poolid"],
                            started_time=event["startedTimeStr"]
                        )
                    # 更新飞书表格
                    process_new_events(events)
                    update_pending_pools(events)
                event_query_triggered = True
            elif current_minute not in [0, 30]:
                event_query_triggered = False
            
            # 2. 整点执行开盘前2小时前的池子查询
            if current_minute == 0 and not hourly_pool_query_triggered:                
                logger.info("=== 触发整点池子查询 ===")
                run_pool_query()
                hourly_pool_query_triggered = True
            elif current_minute != 0:
                hourly_pool_query_triggered = False
            
            # 3. 每10分钟执行开盘前2小时内的池子查询
            if current_minute % 10 == 0 and not ten_min_pool_query_triggered:                
                logger.info("=== 触发每10分钟池子查询 ===")
                run_pool_query()
                ten_min_pool_query_triggered = True
            elif current_minute % 10 != 0:
                ten_min_pool_query_triggered = False
            
            # 休眠10秒，避免CPU占用过高
            time.sleep(10)
        
        except KeyboardInterrupt:
            logger.info("程序被手动终止")
            break
        except Exception as e:
            logger.error(f"主循环异常: {str(e)}", exc_info=True)
            # 异常后休眠1分钟，避免频繁报错
            time.sleep(60)
    
    logger.info("=== BSC PoolStartedAtUpdated 监控程序退出 ===")

if __name__ == "__main__":
    main()