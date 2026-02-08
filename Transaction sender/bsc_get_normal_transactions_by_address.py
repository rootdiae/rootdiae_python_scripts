import requests
import time
import os
import json

# bsc用于API获取指定区块里指定地址的交易的from地址


# 配置参数 - 请根据实际情况修改
API_KEY = ""         # 你的API密钥
INITIAL_FROM_BLOCK = 74166206    # 初始起始区块
INITIAL_TO_BLOCK = 79979821      # 最终结束区块
TARGET_ADDRESS = "0x278d858f05b94576C1E6f73285886876ff6eF8D2"  # 要查询的地址
OUTPUT_FILE = "z_ca_from_addresses.txt"    # 输出文件名
PROGRESS_FILE = "progress.json"           # 进度保存文件名
BLOCK_BATCH_SIZE = 1000                   # 每次查询的区块批次大小（NodeReal限制最大1000块）
MAX_COUNT = 1000                          # 每页最大交易数量
API_URL = f"https://bsc-mainnet.nodereal.io/v1/{API_KEY}"  # BSC主网NodeReal API
RATE_LIMIT_DELAY = 0.5                    # 每次请求之间的延迟（秒）
CU_EXHAUSTED_RETRY_DELAY = 600           # CU配额用完时的重试延迟（秒）
MAX_RETRIES = 5                           # 最大重试次数

def save_progress(current_from_block, from_addresses):
    """保存当前进度到文件"""
    progress_data = {
        "current_from_block": current_from_block,
        "from_addresses": list(from_addresses)
    }
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress_data, f)
    print(f"进度已保存: 已处理到区块 {current_from_block}")


def load_progress():
    """从文件加载进度"""
    if not os.path.exists(PROGRESS_FILE):
        return None, None
    
    try:
        with open(PROGRESS_FILE, "r") as f:
            progress_data = json.load(f)
        current_from_block = progress_data.get("current_from_block")
        from_addresses = set(progress_data.get("from_addresses", []))
        print(f"从进度文件加载: 继续从区块 {current_from_block} 开始处理")
        return current_from_block, from_addresses
    except Exception as e:
        print(f"加载进度文件出错: {e}，将从头开始处理")
        return None, None


def fetch_transactions(from_block, to_block, page_key=None):
    """获取指定区块范围的交易数据，支持分页"""
    # 转换区块号为十六进制
    from_block_hex = hex(from_block)
    to_block_hex = hex(to_block)
    max_count_hex = hex(MAX_COUNT)
    
    # 构建JSON-RPC请求体
    payload = {
        "jsonrpc": "2.0",
        "method": "nr_getTransactionByAddress",
        "params": [{
            "category": ["external"],  # 获取正常交易
            "address": TARGET_ADDRESS,
            "addressType": None,  # 查询所有addressType
            "order": "asc",  # 使用asc顺序确保按区块顺序处理
            "maxCount": max_count_hex,
            "fromBlock": from_block_hex,
            "toBlock": to_block_hex
        }],
        "id": 1
    }
    
    # 如果有pageKey，添加到参数中
    if page_key:
        payload["params"][0]["pageKey"] = page_key
    
    retries = 0
    while retries < MAX_RETRIES:
        try:
            response = requests.post(API_URL, json=payload, timeout=10)
            response.raise_for_status()  # 检查HTTP错误状态
            return response.json()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                # CU配额用完，等待较长时间后重试
                print(f"CU配额已用完，{CU_EXHAUSTED_RETRY_DELAY}秒后重试...")
                time.sleep(CU_EXHAUSTED_RETRY_DELAY)
                retries += 1
            else:
                print(f"HTTP错误: {e}，5秒后重试...")
                time.sleep(5)
                retries += 1
        except requests.exceptions.RequestException as e:
            print(f"请求出错: {e}，5秒后重试...")
            time.sleep(5)
            retries += 1
    
    print(f"已达到最大重试次数 ({MAX_RETRIES})，放弃请求")
    return None

def main():
    # 加载进度
    saved_from_block, saved_addresses = load_progress()
    
    # 初始化进度
    if saved_from_block and saved_addresses:
        current_from_block = saved_from_block
        from_addresses = saved_addresses
    else:
        current_from_block = INITIAL_FROM_BLOCK
        from_addresses = set()
    
    print(f"开始查询区块 {current_from_block} 到 {INITIAL_TO_BLOCK} 之间与地址 {TARGET_ADDRESS} 相关的交易...")
    print(f"每次处理 {BLOCK_BATCH_SIZE} 个区块，每页最多获取 {MAX_COUNT} 条记录")
    
    # 按区块批次处理
    while current_from_block <= INITIAL_TO_BLOCK:
        # 计算当前批次的结束区块
        current_to_block = min(current_from_block + BLOCK_BATCH_SIZE - 1, INITIAL_TO_BLOCK)
        print(f"\n=== 处理区块范围: {current_from_block} - {current_to_block} ===")
        
        page_key = None
        page_count = 0
        
        # 处理当前区块批次的所有交易
        while True:
            page_count += 1
            print(f"\n处理第 {page_count} 页")
            
            # 获取当前页的交易数据
            response_data = fetch_transactions(current_from_block, current_to_block, page_key)
            
            if response_data is None:
                print("请求失败次数过多，保存进度后退出")
                save_progress(current_from_block, from_addresses)
                return
            
            # 检查CU配额错误
            if "error" in response_data:
                error_code = response_data["error"].get("code")
                if error_code == -32005:  # CU配额用完
                    print(f"CU配额已用完，{CU_EXHAUSTED_RETRY_DELAY}秒后重试...")
                    save_progress(current_from_block, from_addresses)
                    time.sleep(CU_EXHAUSTED_RETRY_DELAY)
                    continue
                else:
                    print(f"API错误: {response_data['error'].get('message')}")
                    save_progress(current_from_block, from_addresses)
                    return
            
            # 处理正常响应
            result = response_data.get("result", {})
            transfers = result.get("transfers", [])
            
            if not transfers:
                if page_count == 1:
                    print("当前区块范围内没有交易数据")
                else:
                    print("当前页没有交易数据")
                break
            
            # 提取from地址
            page_addresses = [tx.get("from") for tx in transfers if tx.get("from")]
            from_addresses.update(page_addresses)
            
            print(f"第 {page_count} 页处理完成，新增 {len(page_addresses)} 个地址，累计去重后共 {len(from_addresses)} 个地址")
            
            # 获取下一页的pageKey
            next_page_key = result.get("pageKey")
            if not next_page_key:
                print("已到达当前区块范围的最后一页")
                break
            
            page_key = next_page_key
            time.sleep(RATE_LIMIT_DELAY)  # 避免请求过于频繁
        
        # 保存进度
        save_progress(current_from_block + BLOCK_BATCH_SIZE, from_addresses)
        
        # 移动到下一个区块批次
        current_from_block += BLOCK_BATCH_SIZE
    
    # 保存最终结果
    with open(OUTPUT_FILE, "w") as f:
        for address in sorted(from_addresses):
            f.write(f"{address}\n")
    
    # 删除进度文件（任务完成）
    if os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
    
    print(f"\n处理完成！共获取到 {len(from_addresses)} 个唯一的from地址")
    print(f"结果已保存至 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()