import requests
import json
import csv
from datetime import datetime, timezone
import sys

# 定义Subgraph端点 (需要替换为实际的Uniswap v4 Unichain端点)
SUBGRAPH_ENDPOINT =  "https://gateway.thegraph.com/api/77046aeee2a8664b5de22d61025d4e3c/subgraphs/id/Bd8UnJU8jCRJKVjcW16GHM3FNdfwTojmWb3QwSAmv8Uc"

# 定义流动性池地址
POOL_ADDRESS = "0xc1d4a8a176ff97f6db053f983af4612009414fe93d5498ad2e33ccc3a7e0a26b"

# 定义查询时间范围 (UTC)
START_DATE = "2025-04-16T12:50:00Z"
END_DATE = "2025-04-16T12:50:10Z"

def date_to_unix_timestamp(date_str):
    """将ISO格式的日期字符串转换为Unix时间戳"""
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return int(dt.timestamp())
    except ValueError as e:
        print(f"日期格式错误: {e}")
        sys.exit(1)

def run_query(query):
    """发送GraphQL查询并返回结果"""
    headers = {"Content-Type": "application/json"}
    print(f"执行查询: {SUBGRAPH_ENDPOINT}")
    
    try:
        response = requests.post(SUBGRAPH_ENDPOINT, json={'query': query}, headers=headers)
        response.raise_for_status()  # 检查HTTP请求是否成功
        
        result = response.json()
        
        # 检查GraphQL响应中是否有错误
        if 'errors' in result:
            print(f"GraphQL查询错误: {result['errors']}")
            return None
            
        return result
    
    except requests.exceptions.RequestException as e:
        print(f"查询失败 - HTTP请求错误: {e}")
        if 'response' in locals():
            print(f"响应状态码: {response.status_code}")
            print(f"响应内容: {response.text[:500]}...")  # 显示前500个字符
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
          id
          symbol
          name
        }}
        token1 {{
          id
          symbol
          name
        }}
      }}
    }}
    """
    result = run_query(query)
    if result and 'data' in result and 'pool' in result['data']:
        pool = result['data']['pool']
        print(f"成功获取代币信息: {pool['token0']['symbol']}/{pool['token1']['symbol']}")
        return {
            'token0': pool['token0'],
            'token1': pool['token1']
        }
    else:
        print("无法获取流动性池代币信息")
        return None

def get_swap_txs(start_timestamp, end_timestamp, pool_address, token_info):
    """查询交换交易，支持分页获取所有结果"""
    print(f"正在查询 {pool_address[:8]}... 在 {datetime.fromtimestamp(start_timestamp, timezone.utc)} 到 {datetime.fromtimestamp(end_timestamp, timezone.utc)} 的交换交易...")
    
    all_swaps = []
    skip = 0
    limit = 100  # 每次查询的数量，The Graph最大支持1000
    max_attempts = 5  # 每个分页的最大尝试次数
    
    while True:
        attempt = 0
        while attempt < max_attempts:
            query = f"""
            query {{
              swaps(
                where: {{
                  pool: "{pool_address.lower()}",
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
                amountUSD
                transaction {{
                  id
                }}
              }}
            }}
            """
            
            result = run_query(query)
            
            if result and 'data' in result and 'swaps' in result['data']:
                break  # 查询成功，跳出重试循环
                
            attempt += 1
            print(f"分页查询失败，尝试 {attempt}/{max_attempts}")
            if attempt >= max_attempts:
                print(f"分页查询达到最大尝试次数，跳过此页 ({skip}-{skip+limit})")
                skip += limit  # 跳过此页继续下一页
                continue
        
        if not result or 'data' not in result or 'swaps' not in result['data']:
            break
            
        swaps = result['data']['swaps']
        if not swaps:  # 没有更多结果时退出循环
            break
            
        all_swaps.extend(swaps)
        skip += len(swaps)
        
        print(f"已获取 {len(all_swaps)} 条记录")
    
    print(f"总共找到 {len(all_swaps)} 条交换交易记录")
    
    txs = []
    for swap in all_swaps:
        # 确定是买入还是卖出
        amount0 = float(swap['amount0'])
        amount1 = float(swap['amount1'])
        
        if amount0 < 0 and amount1 > 0:
            # 卖出token0，买入token1
            amount_str = f"卖出 {-amount0:.8f} {token_info['token0']['symbol']}，买入 {amount1:.8f} {token_info['token1']['symbol']}"
            asset_str = f"{token_info['token0']['symbol']} 到 {token_info['token1']['symbol']}"
        elif amount0 > 0 and amount1 < 0:
            # 卖出token1，买入token0
            amount_str = f"卖出 {-amount1:.8f} {token_info['token1']['symbol']}，买入 {amount0:.8f} {token_info['token0']['symbol']}"
            asset_str = f"{token_info['token1']['symbol']} 到 {token_info['token0']['symbol']}"
        else:
            # 这种情况理论上不会发生
            amount_str = f"{amount0:.8f} {token_info['token0']['symbol']} + {amount1:.8f} {token_info['token1']['symbol']}"
            asset_str = f"{token_info['token0']['symbol']} 和 {token_info['token1']['symbol']}"
        
        txs.append({
            'transaction_hash': swap['transaction']['id'],  # 完整的交易哈希
            'date_time': datetime.fromtimestamp(int(swap['timestamp']), timezone.utc).isoformat(),
            'from': swap['sender'],
            'amount': amount_str,
            'asset': asset_str,
            'amount_usd': float(swap['amountUSD']),
            'tx_type': '交换'
        })
    
    return txs

def main():
    # 转换日期为Unix时间戳
    start_timestamp = date_to_unix_timestamp(START_DATE)
    end_timestamp = date_to_unix_timestamp(END_DATE)
    
    print(f"查询时间范围: {START_DATE} 到 {END_DATE}")
    print(f"对应的Unix时间戳: {start_timestamp} 到 {end_timestamp}")
    
    # 获取流动性池代币信息
    token_info = get_pool_tokens()
    if not token_info:
        print("无法获取代币信息，程序退出")
        return
    
    print(f"查询 {POOL_ADDRESS[:8]}... 流动性池的交换交易记录")
    
    # 查询交换交易
    swap_txs = get_swap_txs(start_timestamp, end_timestamp, POOL_ADDRESS, token_info)
    
    print(f"共处理 {len(swap_txs)} 条交换交易记录")
    
    if swap_txs:
        # 计算总交易量
        total_volume = sum(tx['amount_usd'] for tx in swap_txs)
        print(f"总交易金额: ${total_volume:.2f}")
        
        # 构建格式化的文件名
        start_date_str = START_DATE.replace(':', '-')  # 替换冒号，避免文件名问题
        end_date_str = END_DATE.replace(':', '-')
        filename = f"{start_date_str}-{end_date_str}-pool_{POOL_ADDRESS[:8]}_swaps.csv"
        
        # 保存结果到CSV文件
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['transaction_hash', 'date_time', 'from', 'amount', 'asset', 'amount_usd', 'tx_type']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for tx in swap_txs:
                writer.writerow(tx)
        
        print(f"交换交易记录已保存到 {filename}")
        
        # 打印前5条交易作为示例
        print("\n前5条交换交易记录示例:")
        for i, tx in enumerate(swap_txs[:5], 1):
            print(f"\n交易 {i}:")
            print(f"  哈希: {tx['transaction_hash']}")
            print(f"  时间: {tx['date_time']}")
            print(f"  发起地址: {tx['from']}")
            print(f"  数量: {tx['amount']}")
            print(f"  资产: {tx['asset']}")
            print(f"  金额(USD): ${tx['amount_usd']:.2f}")
    else:
        print("未找到符合条件的交换交易记录")

if __name__ == "__main__":
    main()