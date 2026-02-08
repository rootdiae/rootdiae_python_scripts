import requests
import time

# 用于API获取指定区块里指定地址的交易的from地址


# 配置参数 - 请根据实际情况修改
API_KEY = " "         # 你的API密钥
FROM_BLOCK = 79936733    # 起始区块
TO_BLOCK = 79936734      # 结束区块
TARGET_ADDRESS = "0x278d858f05b94576C1E6f73285886876ff6eF8D2"  # 要查询的地址
OUTPUT_FILE = "z_ca_from_addresses.txt"    # 输出文件名
PAGE_SIZE = 1000                      # 每页交易数量
API_URL = "https://api.etherscan.io/v2/api"

def fetch_transactions(page):
    """获取指定页的交易数据"""
    params = {
        "apikey": API_KEY,
        "chainid": "56",  # BSC链的chainid
        "module": "account",
        "action": "txlist",
        "address": TARGET_ADDRESS,
        "startblock": FROM_BLOCK,
        "endblock": TO_BLOCK,
        "page": page,
        "offset": PAGE_SIZE,
        "sort": "desc"
    }
    
    try:
        response = requests.get(API_URL, params=params, timeout=10)
        response.raise_for_status()  # 检查HTTP错误状态
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"请求出错: {e}，5秒后重试...")
        time.sleep(5)
        return fetch_transactions(page)  # 重试

def main():
    from_addresses = set()  # 使用集合自动去重
    current_page = 1
    total_pages = "未知"    # 初始时总页数未知
    
    print(f"开始查询区块 {FROM_BLOCK} 到 {TO_BLOCK} 之间与地址 {TARGET_ADDRESS} 相关的交易...")
    print(f"每页最多获取 {PAGE_SIZE} 条记录")
    
    while True:
        print(f"\n处理第 {current_page} 页 (总页数: {total_pages})")
        
        # 获取当前页的交易数据
        response_data = fetch_transactions(current_page)
        
        # 处理API响应
        if response_data.get("status") == "1":
            transactions = response_data.get("result", [])
            if not transactions:
                print("当前页没有交易数据，结束查询")
                break
            
            # 提取from地址
            page_addresses = [tx.get("from") for tx in transactions if tx.get("from")]
            from_addresses.update(page_addresses)
            
            print(f"第 {current_page} 页处理完成，新增 {len(page_addresses)} 个地址，累计去重后共 {len(from_addresses)} 个地址")
            
            # 判断是否还有更多页
            if len(transactions) < PAGE_SIZE:
                total_pages = current_page
                print(f"已到达最后一页，总页数为 {total_pages}")
                break
            
            current_page += 1
            time.sleep(0.5)  # 避免请求过于频繁
        
        elif response_data.get("status") == "0" and response_data.get("message") == "No transactions found":
            if current_page == 1:
                print("在指定区块范围内未找到任何交易")
            else:
                total_pages = current_page - 1
                print(f"所有数据查询完成，总页数为 {total_pages}")
            break
        
        else:
            # 处理其他错误状态
            print(f"查询出错: 状态码 {response_data.get('status')}，消息: {response_data.get('message')}")
            print("10秒后重试当前页...")
            time.sleep(10)
    
    # 保存结果到文件
    with open(OUTPUT_FILE, "w") as f:
        for address in sorted(from_addresses):
            f.write(f"{address}\n")
    
    print(f"\n处理完成！共获取到 {len(from_addresses)} 个唯一的from地址")
    print(f"结果已保存至 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()