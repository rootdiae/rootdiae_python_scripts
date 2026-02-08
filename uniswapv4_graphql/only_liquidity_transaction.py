import requests
import json
import csv
from datetime import datetime, timezone
import sys
import os
import time

# 定义Subgraph端点
SUBGRAPH_ENDPOINT = "https://gateway.thegraph.com/api/77046aeee2a8664b5de22d61025d4e3c/subgraphs/id/2qQpC8inZPZL4tYfRQPFGZhsE8mYzE67n5z3Yf5uuKMu"

# 定义流动性池地址
POOL_ADDRESS = "0xcf79f5143253c2b29af19617ab6c50128ca29fc70f3e2ea45d0b01a087f8a205"

# 定义查询时间范围 (UTC)
START_DATE = "2025-05-07T00:00:00Z"
END_DATE = "2025-05-21T16:00:00Z"

# UNI 配置
UNI_API_KEY =  ""    # 替换为你的 UniScan API Key
UNI_API_URL =  "https://api.bscscan.com/api"    # UNI 主网 API

def date_to_unix_timestamp(date_str):
    """将ISO格式的日期字符串转换为Unix时间戳"""
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return int(dt.timestamp())
    except ValueError as e:
        print(f"日期格式错误: {e}")
        sys.exit(1)

def run_query(query, save_file_prefix=None):
    """发送GraphQL查询并返回结果，可选保存完整响应到JSON文件"""
    headers = {"Content-Type": "application/json"}
    print(f"执行查询: {SUBGRAPH_ENDPOINT}")
    
    try:
        response = requests.post(SUBGRAPH_ENDPOINT, json={'query': query}, headers=headers)
        response.raise_for_status()  # 检查HTTP请求是否成功
        
        result = response.json()
        
        # 保存完整JSON响应到文件
        if save_file_prefix:
            os.makedirs('graphql_responses', exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"graphql_responses/{save_file_prefix}_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"完整JSON响应已保存到: {filename}")
        
        if 'errors' in result:
            print(f"GraphQL查询错误: {result['errors']}")
            return None
            
        return result
    
    except requests.exceptions.RequestException as e:
        print(f"查询失败 - HTTP请求错误: {e}")
        if 'response' in locals():
            print(f"响应状态码: {response.status_code}")
            print(f"响应内容: {response.text[:500]}...")
        return None
    
    except json.JSONDecodeError as e:
        print(f"查询失败 - JSON解析错误: {e}")
        print(f"响应内容: {response.text[:500]}...") if 'response' in locals() else None
        return None
    
    except Exception as e:
        print(f"查询失败 - 未知错误: {e}")
        return None

def get_pool_tokens():
    """获取流动性池中代币的信息"""
    print("正在获取流动性池代币信息...")
    query = f"""
    query {{
      pool(id: "{POOL_ADDRESS.lower()}") {{
        token0 {{
          symbol
        }}
        token1 {{
          symbol
        }}
      }}
    }}
    """
    result = run_query(query, "pool_tokens")
    if result and 'data' in result and 'pool' in result['data']:
        pool = result['data']['pool']
        print(f"成功获取代币信息: {pool['token0']['symbol']}/{pool['token1']['symbol']}")
        return {
            'token0_symbol': pool['token0']['symbol'],
            'token1_symbol': pool['token1']['symbol']
        }
    else:
        print("无法获取流动性池代币信息")
        return None

def get_liquidity_txs(start_timestamp, end_timestamp, pool_address, token_info, tx_type):
    """查询流动性操作（添加/移除）"""
    print(f"正在查询 {pool_address[:8]}... 的{tx_type}流动性操作...")
    all_txs = []
    skip = 0
    limit = 100
    max_attempts = 5
    operation_field = "modifyLiquiditys"
    
    while True:
        attempt = 0
        while attempt < max_attempts:
            query = f"""
            query {{
              pool(id: "{pool_address.lower()}") {{
                {operation_field}(
                  where: {{
                    timestamp_gte: {start_timestamp},
                    timestamp_lte: {end_timestamp}
                  }},
                  orderBy: timestamp,
                  orderDirection: asc,
                  first: {limit},
                  skip: {skip}
                ) {{
                  id
                  timestamp
                  sender
                  amount0
                  amount1
                }}
              }}
            }}
            """
            result = run_query(query, f"{tx_type}_txs_page_{skip//limit}" if skip == 0 else None)
            if result and 'data' in result and 'pool' in result['data']:
                txs = result['data']['pool'][operation_field]
                break
            attempt += 1
        if not result or not txs:
            break
        
        filtered_txs = []
        for tx in txs:
            amount0 = float(tx['amount0'])
            amount1 = float(tx['amount1'])
            tx_hash = tx['id'].split('-')[0]
            
            if tx_type == "add_liquidity" and amount0 >= 0 and amount1 >= 0:
                filtered_txs.append({
                    **tx,
                    'id': tx_hash,
                    'amount0': amount0,
                    'amount1': amount1
                })
            elif tx_type == "remove_liquidity" and amount0 <= 0 and amount1 <= 0:
                filtered_txs.append({
                    **tx,
                    'id': tx_hash,
                    'amount0': -amount0,
                    'amount1': -amount1
                })
        
        if not filtered_txs:
            break
        
        all_txs.extend(filtered_txs)
        skip += len(txs)
        print(f"已获取 {len(all_txs)} 条{tx_type}记录")
    
    print(f"总共找到 {len(all_txs)} 条{tx_type}记录")
    
    formatted_txs = []
    for tx in all_txs:
        formatted_txs.append({
            'transaction_hash': tx['id'],
            'date_time': datetime.fromtimestamp(int(tx['timestamp']), timezone.utc).isoformat(),
            'from': tx['sender'],  # 这里改为from
            'amount0': float(tx['amount0']),
            'amount1': float(tx['amount1']),
            'tx_type': "添加流动性" if tx_type == "add_liquidity" else "移除流动性"
        })
    return formatted_txs

def get_uni_transaction_details(tx_hash):
    """通过 UniScan API 查询交易的详细信息"""
    params = {
        "module": "proxy",
        "action": "eth_getTransactionByHash",
        "txhash": tx_hash,
        "apikey": UNI_API_KEY
    }
    
    try:
        response = requests.get(UNI_API_URL, params=params)
        data = response.json()
        
        if "result" in data and data["result"]:
            return data["result"]
        else:
            print(f"⚠️ 交易 {tx_hash} 未找到或出错: {data.get('message', '未知错误')}")
            return None
            
    except Exception as e:
        print(f"❌ 查询 {tx_hash} 时发生异常: {str(e)}")
        return None

def main():
    start_timestamp = date_to_unix_timestamp(START_DATE)
    end_timestamp = date_to_unix_timestamp(END_DATE)
    
    print(f"查询时间范围: {START_DATE} 到 {END_DATE}")
    print(f"对应的Unix时间戳: {start_timestamp} 到 {end_timestamp}")
    
    token_info = get_pool_tokens()
    if not token_info:
        print("无法获取代币信息，程序退出")
        return
    
    # 查询添加流动性操作
    add_liquidity_txs = get_liquidity_txs(start_timestamp, end_timestamp, POOL_ADDRESS, token_info, "add_liquidity")
    
    # 查询移除流动性操作
    remove_liquidity_txs = get_liquidity_txs(start_timestamp, end_timestamp, POOL_ADDRESS, token_info, "remove_liquidity")
    
    # 合并所有交易记录
    all_txs = add_liquidity_txs + remove_liquidity_txs
    
    print(f"共处理 {len(all_txs)} 条交易记录")
    
    if all_txs:
        # 生成文件名
        start_date_str = START_DATE.replace(':', '-')
        end_date_str = END_DATE.replace(':', '-')
        filename = f"{start_date_str}-{end_date_str}-pool_{POOL_ADDRESS[:8]}_LP_transactions.csv"
        
        # 定义CSV表头（修改后的字段名）
        fieldnames = ['transaction_hash', 'date_time', 'from', 'sender_address', 'amount0', 'amount1', 'tx_type']
        
        # 写入CSV
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # 添加进度计数器
            processed_count = 0
            total_count = len(all_txs)
            
            for tx in all_txs:
                # 查询UNI交易详情
                uni_details = get_uni_transaction_details(tx['transaction_hash'])
                sender_address = uni_details['from'] if uni_details else "N/A"
                
                writer.writerow({
                    'transaction_hash': tx['transaction_hash'],
                    'date_time': tx['date_time'],
                    'from': tx['from'],  # 使用from字段
                    'sender_address': sender_address,  # 使用sender_address字段
                    'amount0': f"{tx['amount0']:.8f}",
                    'amount1': f"{tx['amount1']:.8f}",
                    'tx_type': tx['tx_type']
                })
                
                # 更新进度计数器并显示进度
                processed_count += 1
                if processed_count % 100 == 0 or processed_count == total_count:
                    print(f"💾 正在保存交易记录: {processed_count}/{total_count} ({processed_count/total_count*100:.1f}%)")
                
                # 避免API速率限制
                time.sleep(1)
        
        print(f"所有交易记录已保存到 {filename}")
        print(f"文件格式示例: {fieldnames}")
        print(f"完整数据请查看 {filename}")

if __name__ == "__main__":
    main()