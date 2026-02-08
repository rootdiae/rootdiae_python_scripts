import requests
import time
import json

# 脚本功能：用交易哈希获取交易发起者地址sender，bscscan用bsc节点，etherscan用eth节点

# BSC 公共节点列表
BSC_PUBLIC_NODES = [
    #"https://eth.llamarpc.com",
    #"https://ethereum.therpc.io",
    #"https://eth1.lava.build",
    #"https://eth-mainnet.public.blastapi.io",
    #"wss://eth.drpc.org"    #eth公共节点

    "https://bsc-dataseed.bnbchain.org",
    "https://wallet.okex.org/fullnode/bsc/discover/rpc",
    "https://bsc-mainnet.public.blastapi.io",
    "https://binance.llamarpc.com",
    "https://bsc-drpc.org",
    "https://bsc-rpc.publicnode.com"       #bsc公共节点
]

INPUT_FILE = "tx_hashes.txt"
OUTPUT_FILE = "bsc_results.csv"
ERROR_LOG_FILE = "error_log.txt"

def get_transaction_from_node(tx_hash, node_url):
    """通过单个 BSC 节点查询交易信息"""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getTransactionByHash",
        "params": [tx_hash],
        "id": 1
    }
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        response = requests.post(node_url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            print(f"❌ 节点返回错误: {data['error']}")
            return None
            
        if "result" in data:
            result = data["result"]
            if result is None:
                print(f"⚠️ 交易未找到: {tx_hash}")
                return None
            elif isinstance(result, dict):
                from_address = result.get("from")
                if from_address:
                    return from_address
                else:
                    print(f"⚠️ 交易中未找到 from 地址: {tx_hash}")
                    return None
        return None
        
    except requests.exceptions.Timeout:
        print(f"⏰ 节点超时: {node_url}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"🌐 网络错误: {str(e)}")
        return None
    except Exception as e:
        print(f"❌ 解析错误: {str(e)}")
        return None

def get_transaction_from_address(tx_hash):
    """通过多个 BSC 节点轮询查询交易信息"""
    print(f"🔍 查询交易: {tx_hash}")
    
    for i, node_url in enumerate(BSC_PUBLIC_NODES):
        print(f"  尝试节点 {i+1}/{len(BSC_PUBLIC_NODES)}: {node_url.split('//')[1].split('/')[0]}")
        
        from_address = get_transaction_from_node(tx_hash, node_url)
        
        if from_address:
            print(f"✅ 成功获取地址: {from_address}")
            return from_address
        
        # 如果不是最后一个节点，稍作延迟
        if i < len(BSC_PUBLIC_NODES) - 1:
            time.sleep(0.1)
    
    print(f"❌ 所有节点查询失败: {tx_hash}")
    return None

def validate_tx_hash(tx_hash):
    """验证交易哈希格式"""
    if not tx_hash:
        return False
    if not tx_hash.startswith('0x'):
        tx_hash = '0x' + tx_hash
    if len(tx_hash) != 66:  # 0x + 64字符
        return False
    try:
        int(tx_hash, 16)
        return True
    except ValueError:
        return False

def format_tx_hash(tx_hash):
    """格式化交易哈希（确保有0x前缀）"""
    if tx_hash.startswith('0x'):
        return tx_hash.lower()
    else:
        return '0x' + tx_hash.lower()

def log_error(tx_hash, error_msg):
    """记录错误日志"""
    with open(ERROR_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{tx_hash},{error_msg}\n")

def main():
    # 读取交易哈希列表
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            tx_hashes = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ 文件 {INPUT_FILE} 未找到！")
        return
    except Exception as e:
        print(f"❌ 读取文件时发生错误: {str(e)}")
        return
    
    if not tx_hashes:
        print("❌ 输入文件为空！")
        return
    
    print(f"🔍 开始查询 {len(tx_hashes)} 笔 BSC 交易...")
    print(f"📋 可用节点数: {len(BSC_PUBLIC_NODES)}")
    
    # 验证交易哈希格式
    valid_tx_hashes = []
    invalid_tx_hashes = []
    
    for tx_hash in tx_hashes:
        if validate_tx_hash(tx_hash):
            valid_tx_hashes.append(format_tx_hash(tx_hash))
        else:
            invalid_tx_hashes.append(tx_hash)
            print(f"⚠️ 无效的交易哈希格式: {tx_hash}")
    
    if invalid_tx_hashes:
        print(f"⚠️ 发现 {len(invalid_tx_hashes)} 个无效的交易哈希")
        with open("invalid_hashes.txt", "w", encoding="utf-8") as f:
            for tx_hash in invalid_tx_hashes:
                f.write(f"{tx_hash}\n")
        print("📝 无效哈希已保存到 invalid_hashes.txt")
    
    if not valid_tx_hashes:
        print("❌ 没有有效的交易哈希可查询！")
        return
    
    print(f"✅ 有效交易哈希数: {len(valid_tx_hashes)}")
    
    # 初始化错误日志文件
    with open(ERROR_LOG_FILE, "w", encoding="utf-8") as f:
        f.write("tx_hash,error_message\n")
    
    successful_count = 0
    failed_count = 0
    
    # 打开输出文件
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f_out:
        f_out.write("tx_hash,from_address\n")
        
        start_time = time.time()
        
        for i, tx_hash in enumerate(valid_tx_hashes, 1):
            print(f"\n[{i}/{len(valid_tx_hashes)}] 处理交易...")
            
            from_address = get_transaction_from_address(tx_hash)
            
            if from_address:
                f_out.write(f"{tx_hash},{from_address}\n")
                successful_count += 1
            else:
                f_out.write(f"{tx_hash},NOT_FOUND\n")
                log_error(tx_hash, "所有节点查询失败")
                failed_count += 1
            
            # 进度统计
            elapsed_time = time.time() - start_time
            avg_time_per_tx = elapsed_time / i
            remaining_time = avg_time_per_tx * (len(valid_tx_hashes) - i)
            
            print(f"📊 进度: {i}/{len(valid_tx_hashes)} | 成功: {successful_count} | 失败: {failed_count}")
            print(f"⏱️  预计剩余时间: {remaining_time/60:.1f} 分钟")
            
            # 请求间隔以避免被限制
            if i < len(valid_tx_hashes):
                time.sleep(0.3)
        
        total_time = time.time() - start_time
    
    # 输出统计信息
    print(f"\n" + "="*50)
    print("🎉 查询完成！")
    print(f"✅ 成功: {successful_count}")
    print(f"❌ 失败: {failed_count}")
    print(f"⚠️  无效哈希: {len(invalid_tx_hashes)}")
    print(f"⏱️  总耗时: {total_time/60:.2f} 分钟")
    print(f"📁 结果文件: {OUTPUT_FILE}")
    print(f"📁 错误日志: {ERROR_LOG_FILE}")
    if invalid_tx_hashes:
        print(f"📁 无效哈希: invalid_hashes.txt")
    print("="*50)

if __name__ == "__main__":
    main()