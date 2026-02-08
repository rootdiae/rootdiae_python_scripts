import requests
import pandas as pd
from datetime import datetime, timezone
import time

# ======================
# 配置参数（用于筛选币安alpha代币指定时间内买入卖出交易数据）
# ======================
API_KEY = " "  # 替换为你的 API Key
BSC_API_KEY = " "  # 替换为你的 API Key
ADDRESS = "0x73D8bD54F7Cf5FAb43fE4Ef40A62D390644946Db".lower()  # 目标地址（统一小写）币安的alpha地址
TOKEN_ADDRESS = "0x75a5863a19af60ec0098d62ed8c34cc594fb470f"  # 代币合约地址
START_DATE_UTC = "2025-07-06 13:30:00"  # UTC时间（开始时间）
END_DATE_UTC = "2025-07-06 14:00:00"    # UTC时间（结束时间）
MIN_AMOUNT = 5000  # 最小金额（代币数量）
MAX_AMOUNT = 10000000000  # 最大金额（代币数量）

# ======================
# 时间戳与区块高度转换
# ======================
def get_block_by_timestamp(timestamp: int, closest: str = "before") -> int:
    """根据时间戳获取对应的区块高度"""
    url =  "https://api.bscscan.com/api"  
    params = {
        "module": "block",
        "action": "getblocknobytime",
        "timestamp": timestamp,
        "closest": closest,
        "apikey": API_KEY
    }
    try:
        response = requests.get(url, params=params, timeout=30)
        data = response.json()
        if data["status"] != "1":
            print(f"[区块查询错误] {data.get('message', 'Unknown error')}")
            return None
        return int(data["result"])
    except Exception as e:
        print(f"[区块查询异常] {e}")
        return None

# 转换时间为UTC时间戳并生成文件名时间部分
start_dt = datetime.strptime(START_DATE_UTC, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
end_dt = datetime.strptime(END_DATE_UTC, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
start_ts = int(start_dt.timestamp())
end_ts = int(end_dt.timestamp())

# 生成文件名中的时间格式（YYYYMMDD_HHMMSS）
file_start_time = start_dt.strftime("%Y%m%d_%H%M%S")
file_end_time = end_dt.strftime("%Y%m%d_%H%M%S")

# ======================
# 交易数据获取与筛选
# ======================
def get_transactions_by_block(address: str, contract: str, start_blk: int, end_blk: int, page: int = 1) -> list:
    """通过区块范围分页获取交易记录"""
    url =  "https://api.bscscan.com/api"  
    params = {
        "module": "account",
        "action": "tokentx",
        "address": address,
        "contractaddress": contract,
        "startblock": start_blk,
        "endblock": end_blk,
        "page": page,
        "offset": 1000,  # 单次最多获取1000条
        "sort": "asc",
        "apikey": API_KEY
    }
    try:
        response = requests.get(url, params=params, timeout=30)
        data = response.json()
        if data["status"] != "1":
            print(f"[交易查询错误] {data.get('message', 'Unknown error')}")
            return []
        return data["result"]
    except Exception as e:
        print(f"[交易查询异常] {e}")
        return []

# ======================
# BSC交易查询函数
# ======================
def get_transaction_from_address(tx_hash):
    """通过 BscScan API 查询交易的 from 地址"""
    BSC_API_URL =  "https://api.bscscan.com/api"  
    params = {
        "module": "proxy",
        "action": "eth_getTransactionByHash",
        "txhash": tx_hash,
        "apikey": BSC_API_KEY
    }
    
    try:
        response = requests.get(BSC_API_URL, params=params)
        data = response.json()
        
        if "result" in data and data["result"]:
            return data["result"]["from"]
        else:
            print(f"⚠️ 交易 {tx_hash} 未找到或出错: {data.get('message', '未知错误')}")
            return None
            
    except Exception as e:
        print(f"❌ 查询 {tx_hash} 时发生异常: {str(e)}")
        return None

# ======================
# 交易筛选逻辑
# ======================
def filter_transactions(txs: list, start_ts: int, end_ts: int, min_amt: float, max_amt: float) -> list:
    """筛选符合条件的交易"""
    filtered = []
    time_filter = 0
    amount_filter = 0
    direction_filter = 0

    for tx in txs:
        try:
            tx_time = int(tx["timeStamp"])
            tx_from = tx["from"].lower()
            tx_to = tx["to"].lower()
            tx_value_raw = int(tx["value"])
            tx_decimal = int(tx["tokenDecimal"])
            tx_amount = tx_value_raw / (10 ** tx_decimal)

            # 时间与金额筛选
            if not (start_ts <= tx_time <= end_ts):
                time_filter += 1
                continue
            if not (min_amt <= tx_amount <= max_amt):
                amount_filter += 1
                continue

            # 方向筛选（转入/转出ADDRESS）
            if tx_from == ADDRESS or tx_to == ADDRESS:
                filtered.append(tx)
            else:
                direction_filter += 1

        except Exception as e:
            print(f"[跳过异常交易] {e}")
            continue

    print(f"\n[筛选统计]")
    print(f"  时间过滤: {time_filter} 条")
    print(f"  金额过滤: {amount_filter} 条")
    print(f"  方向过滤: {direction_filter} 条")
    print(f"  最终匹配: {len(filtered)} 条")
    return filtered

# ======================
# 主程序
# ======================
def main():
    # 分页获取所有交易
    all_transactions = []
    current_page = 1
    start_block = get_block_by_timestamp(start_ts, closest="before")
    end_block = get_block_by_timestamp(end_ts, closest="after")

    if start_block is None or end_block is None:
        print("无法获取区块高度，程序终止")
        exit()

    print(f"[时间范围] UTC {START_DATE_UTC} ~ {END_DATE_UTC}")
    print(f"[对应区块] 从 {start_block} 到 {end_block}")

    while True:
        txs = get_transactions_by_block(ADDRESS, TOKEN_ADDRESS, start_block, end_block, page=current_page)
        if not txs:
            break
        all_transactions.extend(txs)
        print(f"已获取第 {current_page} 页，{len(txs)} 条交易（累计 {len(all_transactions)} 条）")
        current_page += 1
        time.sleep(1)  # 避免请求过快

    print(f"\n[数据汇总] 共获取 {len(all_transactions)} 条原始交易记录")

    # 筛选交易
    filtered_txs = filter_transactions(all_transactions, start_ts, end_ts, MIN_AMOUNT, MAX_AMOUNT)

    # 结果导出
    if filtered_txs:
        # 获取代币符号（假设交易列表非空时第一个交易包含tokenSymbol）
        token_symbol = filtered_txs[0].get("tokenSymbol", "UNKNOWN")
        
        # 生成文件名：代币符号+开始时间+结束时间+后缀
        file_name = f"{token_symbol}_{file_start_time}_{file_end_time}_filtered_transactions.csv"
        
        # 转换为DataFrame并格式化
        df = pd.DataFrame(filtered_txs)
        df["交易时间(UTC)"] = pd.to_datetime(df["timeStamp"].astype(int), unit="s", utc=True)
        df["实际交易金额"] = df.apply(lambda x: int(x["value"]) / (10**int(x["tokenDecimal"])), axis=1)
        df["交易方向"] = df.apply(lambda x: "转出" if x["from"]==ADDRESS else "转入", axis=1)
        
        # 查询每个交易的from_address（原始发送方）
        print("\n[开始查询原始发送方地址]")
        from_addresses = []
        for i, tx_hash in enumerate(df["hash"], 1):
            print(f"[{i}/{len(df)}] 查询交易 {tx_hash}...")
            from_address = get_transaction_from_address(tx_hash)
            from_addresses.append(from_address)
            time.sleep(0.2)  # 避免API速率限制
        
        # 添加from_address到DataFrame
        df["原始发送方"] = from_addresses
        
        # 保留关键列并排序
        df = df[["blockNumber", "交易时间(UTC)", "hash", "from", "to", "实际交易金额", "tokenSymbol", "交易方向", "原始发送方"]]
        df.sort_values("交易时间(UTC)", inplace=True)
        
        # 导出文件
        df.to_csv(file_name, index=False, encoding="utf-8-sig")
        print(f"\n[文件导出成功] 路径：{file_name}")
        print(f"数据量：{len(filtered_txs)} 条")
        print("文件字段：区块高度, 交易时间(UTC), 交易哈希, 转出地址, 转入地址, 实际金额, 代币符号, 交易方向, 原始发送方")
    else:
        print("\n[结果为空] 未找到符合条件的交易记录")

if __name__ == "__main__":
    main()