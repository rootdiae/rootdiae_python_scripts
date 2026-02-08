import json
import time
from web3 import Web3
from openpyxl import Workbook

# 配置
CONTRACT_ADDRESS = "0x4529A01c7A0410167c5740C487A8DE60232617bf"
RPC_URL = "https://unichain-rpc.publicnode.com"  # 免费公共节点（可替换为 Infura/Alchemy）
START_TOKEN_ID = 34523
END_TOKEN_ID = 45117
OUTPUT_FILE = "uniswap_v4_positions.xlsx"

# Uniswap V4 部分 ABI（仅包含必要方法）
ABI = '''
[
    {
        "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
        "name": "getPoolAndPositionInfo",
        "outputs": [
            {"components": [
                {"internalType": "address", "name": "token0", "type": "address"},
                {"internalType": "address", "name": "token1", "type": "address"},
                {"internalType": "uint24", "name": "fee", "type": "uint24"},
                {"internalType": "int24", "name": "tickSpacing", "type": "int24"},
                {"internalType": "address", "name": "hook", "type": "address"}
            ], "internalType": "struct PoolKey", "name": "poolKey", "type": "tuple"},
            {"internalType": "uint256", "name": "info", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]
'''

# 初始化 Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

def fetch_and_save_positions():
    wb = Workbook()
    ws = wb.active
    ws.title = "Uniswap V4 Positions"
    ws.append([
        "Token ID",
        "Token 0",
        "Token 1",
        "Fee Tier",
        "Tick Spacing",
        "Hook Address",
        "Info (hex)"
    ])

    for token_id in range(START_TOKEN_ID, END_TOKEN_ID + 1):
        try:
            # 调用合约方法
            result = contract.functions.getPoolAndPositionInfo(token_id).call()
            print(result)
            pool_key, info = result

            # 解析 poolKey
            token0 = pool_key[0]
            token1 = pool_key[1]
            fee = pool_key[2]
            tick_spacing = pool_key[3]
            hook = pool_key[4]

            # 写入 Excel
            ws.append([
                token_id,
                token0,
                token1,
                fee,
                tick_spacing,
                hook,
                hex(info)  # 将 uint256 转换为十六进制
            ])

            print(f"✅ Token ID {token_id} fetched")
            time.sleep(0.2)  # 避免 RPC 速率限制

        except Exception as e:
            print(f"❌ Error fetching Token ID {token_id}: {e}")
            continue

    # 保存文件
    wb.save(OUTPUT_FILE)
    print(f"\n🎉 Data saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    fetch_and_save_positions()