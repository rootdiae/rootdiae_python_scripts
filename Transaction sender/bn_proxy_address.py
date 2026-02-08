import requests
import time
import logging
import os
from typing import List, Dict, Optional, Generator
from dataclasses import dataclass

# 此脚本用于获取bn代理地址。先获取指定区块范围内指定topic0的交易哈希，再通过哈希获取完整交易日志，筛选符合条件的transfer事件，最后提取目标地址并保存。
# 文件输出为txt文件，保存到当前目录下。会自动过滤重复地址。会记录进度到状态文件，可中断后续继续。


# 禁用SSL警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 代理配置
PROXY_CONFIG = {
    'http': 'http://127.0.0.1:40880',
    'https': 'http://127.0.0.1:40880'
}

# 节点配置 - 分开设置两种节点
@dataclass
class NodeConfig:
    urls: List[str]
    retry_delay: int = 60  # 节点冷却时间(秒)
    request_interval: float = 0.5  # 请求间隔(秒)
    max_retries: int = 3  # 最大重试次数

# 区块日志节点配置（用于eth_getLogs获取指定区块范围内的日志）
BLOCK_LOGS_NODES = NodeConfig(
    urls=[
        "https://bsc.drpc.org",
        "https://wallet.okex.org/fullnode/bsc/discover/rpc",
        "https://bsc-rpc.publicnode.com"
        # 添加更多区块日志节点
    ],
    request_interval=1.0,  # eth_getLogs通常更消耗资源，间隔稍长
    max_retries=10
)

# 交易收据节点配置（用于eth_getTransactionReceipt获取完整的交易日志）
TRANSACTION_NODES = NodeConfig(
    urls=[
        "https://bsc.publicnode.com",  # 官方节点
        "https://bsc-mainnet.gateway.pokt.network/v1/lb/6136201a7bad1500343e248d",
        "https://bsc-dataseed.binance.org/",  # 不带数字的
        "https://bsc-dataseed4.binance.org/",
        "https://bsc.nodereal.io",
        "https://bsc-dataseed.bnbchain.org",
        "https://wallet.okex.org/fullnode/bsc/discover/rpc",
        "https://bsc-mainnet.public.blastapi.io",
        "https://binance.llamarpc.com",
        "https://bsc.drpc.org",
        "https://bsc-rpc.publicnode.com"
    ],
    request_interval=0.3,  # 交易查询可以更频繁
    max_retries=10
)


# 其他配置参数
TARGET_ADDRESS = "0x3d90f66B534Dd8482b181e24655A9e8265316BE9"
TOPIC0_FIRST = "0xe5b9f85c5caca875a8b78e5b2d88de86d7793cbff3d81ea4ecbec4c2b9ad7beb"
TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
FROM_TARGET_WALLET = "0x0000000000000000000000006aba0315493b7e6989041C91181337b662fB1b90".lower() # BN 2.0 ALPHA地址
TO_TARGET_WALLET = "0x0000000000000000000000006aba0315493b7e6989041C91181337b662fB1b90".lower()

# 区块范围设置 - 根据需要调整
START_BLOCK = 76877324    # 初始起始区块
END_BLOCK = 77432021  # 结束区块
BATCH_SIZE = 1000         # 每次请求的区块数量
OUTPUT_FILE = f"{START_BLOCK}_{END_BLOCK}_bn_alpha_2.txt"
STATUS_FILE = f"{START_BLOCK}_{END_BLOCK}_status_2.txt"  # 进度状态文件

# 全局变量，存储已收集的地址（内存中去重，避免同一批次重复）
collected_addresses = set()


class NodeManager:
    """节点管理器，负责单个类型节点的轮换和状态管理"""
    
    def __init__(self, config: NodeConfig):
        self.config = config
        self.last_failed = {url: 0 for url in config.urls}
        self.last_request_time = 0  # 最后一次请求时间，用于控制频率
        
        # 创建带代理配置的session
        self.session = requests.Session()
        self.session.proxies = PROXY_CONFIG
        
        # 针对SSL问题，可以尝试调整验证设置
        # 注意：verify=False会降低安全性，仅在必要时使用
        self.session.verify = False
        
        # 设置默认请求头
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })
        
        # 配置重试策略
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def get_node_generator(self) -> Generator[str, None, None]:
        """生成可用节点的迭代器"""
        while True:
            for url in self.config.urls:
                # 检查节点是否在冷却期
                if time.time() - self.last_failed[url] < self.config.retry_delay:
                    continue
                yield url
            
            # 所有节点都尝试过，等待一会再重试
            logger.warning(f"所有{len(self.config.urls)}个节点均暂时不可用，等待重试...")
            time.sleep(10)
    
    def make_request(self, method: str, params: List) -> Optional[Dict]:
        """使用当前节点配置发送请求，带频率控制和重试"""
        # 控制请求频率
        now = time.time()
        time_since_last = now - self.last_request_time
        if time_since_last < self.config.request_interval:
            time.sleep(self.config.request_interval - time_since_last)
        self.last_request_time = time.time()
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": int(time.time())
        }
        
        node_gen = self.get_node_generator()
        
        # 尝试多个节点
        for attempt in range(self.config.max_retries):
            node_url = next(node_gen)
            try:
                logger.debug(f"使用节点 {node_url} 发送{method}请求 (尝试{attempt+1}/{self.config.max_retries})")
                
                # 使用带代理的session发送请求
                response = self.session.post(node_url, json=payload, timeout=30)
                response.raise_for_status()
                result = response.json()
                
                if "error" in result:
                    logger.warning(f"节点 {node_url} 返回错误: {result['error']}")
                    # 错误响应也视为失败，记录时间但继续尝试其他节点
                    self.last_failed[node_url] = time.time()
                    continue
                    
                return result.get("result")
                
            except requests.exceptions.SSLError as e:
                logger.warning(f"节点 {node_url} SSL错误: {str(e)}")
                # SSL错误时，尝试临时调整SSL验证
                try:
                    # 临时尝试不使用代理或使用不同的验证方式
                    temp_session = requests.Session()
                    temp_session.verify = False
                    temp_session.proxies = PROXY_CONFIG
                    response = temp_session.post(node_url, json=payload, timeout=30)
                    response.raise_for_status()
                    result = response.json()
                    
                    if "error" in result:
                        logger.warning(f"节点 {node_url} 返回错误: {result['error']}")
                        self.last_failed[node_url] = time.time()
                        continue
                        
                    return result.get("result")
                    
                except Exception as e2:
                    logger.warning(f"节点 {node_url} 备用请求也失败: {str(e2)}")
                    self.last_failed[node_url] = time.time()
                    continue
                    
            except requests.exceptions.RequestException as e:
                logger.warning(f"节点 {node_url} 请求失败: {str(e)}")
                self.last_failed[node_url] = time.time()
                continue
        
        logger.error(f"超过最大重试次数，无法完成{method}请求")
        return None


def check_transfer_conditions(logs: List[Dict]) -> bool:
    """检查交易日志是否包含符合条件的transfer事件"""
    transfer_logs = [log for log in logs if log.get("topics", [])[0] == TRANSFER_TOPIC0]
    
    has_topic1_match = any(
        len(log.get("topics", [])) >= 3 and log["topics"][1] == FROM_TARGET_WALLET
        for log in transfer_logs
    )
    
    has_topic2_match = any(
        len(log.get("topics", [])) >= 3 and log["topics"][2] == TO_TARGET_WALLET
        for log in transfer_logs
    )
    
    return has_topic1_match and has_topic2_match


def extract_target_address(data: str) -> Optional[str]:
    """从data中提取目标地址"""
    try:
        # 去掉前缀0x，从第216个字符开始取40个字符，然后添加0x前缀
        cleaned_data = data[2:]  # 去掉0x
        if len(cleaned_data) < 216 + 40:
            logger.warning(f"data长度不足: {data}")
            return None
            
        target_part = cleaned_data[216:216+40]
        return f"0x{target_part}"
    except Exception as e:
        logger.error(f"提取地址失败: {str(e)}")
        return None


def load_progress() -> int:
    """从状态文件加载上次处理到的区块号"""
    if not os.path.exists(STATUS_FILE):
        logger.info("未找到进度文件，将从初始区块开始处理")
        return START_BLOCK
    
    try:
        with open(STATUS_FILE, "r") as f:
            content = f.read().strip()
            if not content:
                logger.warning("进度文件为空，从初始区块开始处理")
                return START_BLOCK
            
            last_processed_block = int(content)
            # 验证区块号的合理性
            if last_processed_block < START_BLOCK:
                logger.warning(f"进度文件中的区块号({last_processed_block})小于起始区块，从初始区块开始处理")
                return START_BLOCK
            if last_processed_block >= END_BLOCK:
                logger.info(f"所有区块已处理完成（上次处理到{last_processed_block}）")
                return END_BLOCK + 1  # 返回一个超过结束区块的值，触发完成逻辑
            
            logger.info(f"成功加载进度，上次处理到区块: {last_processed_block}")
            # 返回下一个要处理的批次起始区块
            return last_processed_block + 1
    except Exception as e:
        logger.error(f"读取进度文件失败: {str(e)}，将从初始区块开始处理")
        return START_BLOCK


def save_progress(last_processed_block: int):
    """保存当前处理进度到状态文件"""
    try:
        with open(STATUS_FILE, "w") as f:
            f.write(str(last_processed_block))
        logger.debug(f"已保存进度到区块: {last_processed_block}")
    except Exception as e:
        logger.error(f"保存进度文件失败: {str(e)}")


def append_addresses_to_file(addresses: set):
    """将新收集的地址追加保存到文件（不去重，仅追加）"""
    if not addresses:
        return
    
    try:
        with open(OUTPUT_FILE, "a") as f:
            for address in addresses:
                f.write(f"{address}\n")
        logger.info(f"已追加 {len(addresses)} 个新地址到文件")
    except Exception as e:
        logger.error(f"保存地址到文件失败: {str(e)}")


def deduplicate_output_file():
    """对输出文件中的地址进行去重"""
    if not os.path.exists(OUTPUT_FILE):
        logger.warning("输出文件不存在，无需去重")
        return
    
    try:
        # 读取所有地址并去重
        with open(OUTPUT_FILE, "r") as f:
            all_lines = f.readlines()
            unique_addresses = set(line.strip() for line in all_lines if line.strip())
        
        # 重新写入去重后的地址
        with open(OUTPUT_FILE, "w") as f:
            for address in sorted(unique_addresses):
                f.write(f"{address}\n")
        
        logger.info(f"去重完成，最终保留 {len(unique_addresses)} 个唯一地址")
    except Exception as e:
        logger.error(f"地址去重失败: {str(e)}")


def cleanup_status_file():
    """处理完成后删除状态文件"""
    try:
        if os.path.exists(STATUS_FILE):
            os.remove(STATUS_FILE)
            logger.info("处理完成，已删除进度文件")
    except Exception as e:
        logger.warning(f"删除进度文件失败: {str(e)}")


def main():
    global collected_addresses
    
    # 加载上次处理进度
    current_start_block = load_progress()
    
    # 如果已经处理完成，直接去重并退出
    if current_start_block > END_BLOCK:
        logger.info("开始对所有地址进行最终去重...")
        deduplicate_output_file()
        cleanup_status_file()
        return
    
    # 初始化两种节点管理器
    block_logs_manager = NodeManager(BLOCK_LOGS_NODES)
    transaction_manager = NodeManager(TRANSACTION_NODES)
    
    # 加载已保存的地址到内存（避免同一地址在不同批次重复追加）
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r") as f:
                existing_addresses = set(line.strip() for line in f.readlines() if line.strip())
            collected_addresses = existing_addresses
            logger.info(f"已加载 {len(collected_addresses)} 个已保存的地址")
        except Exception as e:
            logger.warning(f"加载已保存地址失败: {str(e)}，将重新开始收集")
            collected_addresses = set()
    
    try:
        # 分批次处理区块范围（从上次中断的区块开始）
        for from_block in range(current_start_block, END_BLOCK + 1, BATCH_SIZE):
            to_block = min(from_block + BATCH_SIZE - 1, END_BLOCK)
            batch_new_addresses = set()  # 本批次新收集的地址
            
            logger.info(f"\n===== 开始处理区块 {from_block} 到 {to_block} =====")
            
            # 第一步：使用区块日志节点获取指定条件的日志
            logger.info(f"获取区块 {from_block} 到 {to_block} 的日志...")
            params = [{
                "address": TARGET_ADDRESS,
                "topics": [TOPIC0_FIRST],
                "fromBlock": hex(from_block),
                "toBlock": hex(to_block)
            }]
            first_logs = block_logs_manager.make_request("eth_getLogs", params)
            first_logs = first_logs if first_logs is not None else []
            
            logger.info(f"在区块 {from_block}-{to_block} 找到 {len(first_logs)} 条符合条件的日志")
            
            if first_logs:
                # 处理每条日志
                for log in first_logs:
                    tx_hash = log.get("transactionHash")
                    data = log.get("data")
                    
                    if not tx_hash or not data:
                        logger.warning("日志缺少transactionHash或data字段，跳过")
                        continue
                    
                    # 第二步：使用交易节点获取交易完整日志并检查条件
                    logger.debug(f"处理交易: {tx_hash}")
                    receipt = transaction_manager.make_request("eth_getTransactionReceipt", [tx_hash])
                    
                    if not receipt or "logs" not in receipt:
                        logger.warning(f"无法获取交易收据: {tx_hash}，跳过")
                        continue
                    
                    if check_transfer_conditions(receipt["logs"]):
                        # 第三步：提取目标地址
                        target_address = extract_target_address(data)
                        if target_address:
                            # 内存中去重（避免同一地址多次追加）
                            if target_address not in collected_addresses:
                                collected_addresses.add(target_address)
                                batch_new_addresses.add(target_address)
                                logger.debug(f"提取到新地址: {target_address}")
            
            # 批次处理完成，保存进度和新地址
            logger.info(f"区块 {from_block}-{to_block} 处理完成，本批次新增 {len(batch_new_addresses)} 个地址")
            append_addresses_to_file(batch_new_addresses)
            save_progress(to_block)  # 保存当前批次的结束区块作为进度
        
        # 所有区块处理完成
        logger.info("\n===== 所有区块处理完成！=====")
        deduplicate_output_file()
        cleanup_status_file()
        logger.info(f"最终结果已保存到: {OUTPUT_FILE}")
    
    except KeyboardInterrupt:
        logger.warning("\n程序被用户中断，已保存当前进度")
        # 保存最后处理到的区块（如果当前正在处理某个批次）
        if 'to_block' in locals():
            save_progress(to_block)
        append_addresses_to_file(batch_new_addresses if 'batch_new_addresses' in locals() else set())
        logger.info(f"当前进度已保存，下次启动将从区块 {to_block + 1 if 'to_block' in locals() else current_start_block} 继续")
    except Exception as e:
        logger.error(f"\n程序异常退出: {str(e)}", exc_info=True)
        # 异常时也保存进度
        if 'to_block' in locals():
            save_progress(to_block)
        append_addresses_to_file(batch_new_addresses if 'batch_new_addresses' in locals() else set())
        logger.info(f"异常退出前已保存进度，下次启动将从区块 {to_block + 1 if 'to_block' in locals() else current_start_block} 继续")


if __name__ == "__main__":
    main()