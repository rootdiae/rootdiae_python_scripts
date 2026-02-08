from web3 import Web3
import json
import time
from typing import List, Dict, Any

class TransactionEventsFetcher:
    def __init__(self, rpc_url: str):
        """
        初始化交易事件获取器
        
        参数:
        rpc_url (str): Ethereum节点RPC URL
        """
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError("无法连接到以太坊节点")
        print("成功连接到以太坊节点")
    
    def get_transaction_events(self, tx_hash: str) -> Dict[str, Any]:
        """
        获取单笔交易的所有事件日志
        
        参数:
        tx_hash (str): 交易哈希
        
        返回:
        dict: 包含交易收据和事件日志的字典
        """
        try:
            # 确保tx_hash是正确格式
            if not tx_hash.startswith('0x'):
                tx_hash = '0x' + tx_hash
            
            # 获取交易收据
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            
            if receipt is None:
                return {
                    'transaction_hash': tx_hash,
                    'error': '交易收据不存在或尚未确认',
                    'success': False
                }
            
            # 解析事件日志
            events = []
            for log in receipt.logs:
                event = {
                    'log_index': log.logIndex,
                    'transaction_index': log.transactionIndex,
                    'transaction_hash': log.transactionHash.hex(),
                    'block_hash': log.blockHash.hex(),
                    'block_number': log.blockNumber,
                    'address': log.address,
                    'data': log.data,
                    'topics': [topic.hex() for topic in log.topics],
                    'removed': log.removed
                }
                events.append(event)
            
            result = {
                'transaction_hash': tx_hash,
                'status': receipt.status,  # 1表示成功，0表示失败
                'block_number': receipt.blockNumber,
                'gas_used': receipt.gasUsed,
                'cumulative_gas_used': receipt.cumulativeGasUsed,
                'contract_address': receipt.contractAddress,
                'logs_count': len(receipt.logs),
                'events': events,
                'success': True
            }
            
            return result
            
        except Exception as e:
            return {
                'transaction_hash': tx_hash,
                'error': str(e),
                'success': False
            }
    
    def batch_get_events(self, tx_hashes: List[str], delay: float = 0.1) -> List[Dict[str, Any]]:
        """
        批量获取多笔交易的事件日志
        
        参数:
        tx_hashes (List[str]): 交易哈希列表
        delay (float): 请求之间的延迟时间（秒），避免速率限制
        
        返回:
        List[Dict]: 所有交易的事件日志列表
        """
        results = []
        
        for i, tx_hash in enumerate(tx_hashes):
            print(f"处理交易 {i+1}/{len(tx_hashes)}: {tx_hash}")
            
            result = self.get_transaction_events(tx_hash)
            results.append(result)
            
            # 添加延迟以避免速率限制
            if i < len(tx_hashes) - 1:  # 最后一个请求后不需要延迟
                time.sleep(delay)
        
        return results
    
    def save_to_json(self, data: List[Dict[str, Any]], filename: str):
        """
        将数据保存为JSON文件
        
        参数:
        data: 要保存的数据
        filename: 输出文件名
        """
        # 转换无法JSON序列化的对象
        def default_serializer(obj):
            if isinstance(obj, bytes):
                return obj.hex()
            raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=default_serializer, ensure_ascii=False)
        
        print(f"数据已保存到 {filename}")

def main():
    # 配置RPC节点URL（需要替换为你自己的）
    RPC_URL = "https://bsc.drpc.org"  # 替换为你的Infura项目ID
    # 或者使用其他RPC服务：https://rpc.ankr.com/eth, https://eth.llamarpc.com等
    
    # 配置多笔交易哈希（示例交易）
    TRANSACTION_HASHES = [
        "0x8e7deb1b30179b72ba91b52141b0436e07af89f373546f0de74de42be4a7699f"
    ]
    
    # 输出文件名
    OUTPUT_FILE = "transaction_events.json"
    
    try:
        # 初始化获取器
        fetcher = TransactionEventsFetcher(RPC_URL)
        
        # 批量获取事件日志
        print(f"开始获取 {len(TRANSACTION_HASHES)} 笔交易的事件日志...")
        results = fetcher.batch_get_events(TRANSACTION_HASHES, delay=0.2)
        
        # 统计结果
        successful = sum(1 for result in results if result.get('success', False))
        failed = len(results) - successful
        
        print(f"\n处理完成！成功: {successful}, 失败: {failed}")
        
        # 保存到JSON文件
        fetcher.save_to_json(results, OUTPUT_FILE)
        
        # 打印简要信息
        print("\n交易结果摘要:")
        for result in results:
            status = "✓" if result.get('success', False) else "✗"
            error = result.get('error', '')
            print(f"{status} {result['transaction_hash']} {error}")
            
    except Exception as e:
        print(f"程序执行出错: {e}")

if __name__ == "__main__":
    main()