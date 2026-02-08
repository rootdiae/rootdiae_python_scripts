from web3 import Web3, HTTPProvider
from decimal import Decimal
import time
import os
from dotenv import load_dotenv

# bsc测试网的pancake v2的swap交易，在交易前查询预期价格

# 加载环境变量
load_dotenv()

# === 核心配置 ===
TRADE_DIRECTION = 1  # 0=反向（USDT→WBNB），1=正向（WBNB→USDT）
RPC_URL = "https://bsc-testnet-rpc.publicnode.com"  # BSC 测试网 RPC
PRIVATE_KEY = os.getenv("PRIVATE_KEY")  # 从环境变量读取私钥
SLIPPAGE_TOLERANCE = 0.01  # 1% 滑点容忍度，可调整

# BSC 测试网 PancakeSwap 路由器地址
SWAP_CONTRACT_ADDRESS = Web3.to_checksum_address("0x9Ac64Cc6e4415144C455BD8E4837Fea55603e5c3")

# BSC 测试网代币地址
TOKENS = {
    "WBNB": Web3.to_checksum_address("0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd"),  # WBNB
    "USDC": Web3.to_checksum_address("0x64544969ed7EBf5f083679233325356EbE738930")   # USDT
}

FEE = 3000  # PancakeSwap 常用费率 0.3%
DEADLINE = int(time.time() + 600)  # 交易截止时间
AUTHORIZED = False  # 授权状态标记（一次授权后无需重复）


# === 合约ABI（PancakeSwap Router） ===
SWAP_ABI = [
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactTokensForTokens",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountOut", "type": "uint256"},
            {"internalType": "uint256", "name": "amountInMax", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapTokensForExactTokens",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"}
        ],
        "name": "getAmountsOut",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountOut", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"}
        ],
        "name": "getAmountsIn",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "view",
        "type": "function"
    }
]

ERC20_ABI = [
    {"constant": False, "inputs": [{"name": "_spender", "type": "address"}, {"name": "_value", "type": "uint256"}],
     "name": "approve", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "account", "type": "address"}], "name": "balanceOf",
     "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"}
]


# === 核心工具函数 ===
def get_token_symbol(web3, token_address):
    """获取代币符号"""
    try:
        contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)
        return contract.functions.symbol().call()
    except:
        return "Unknown"

def get_decimals(web3, token):
    return web3.eth.contract(address=token, abi=ERC20_ABI).functions.decimals().call()


def print_balances(web3, from_token, to_token, user_addr):
    """打印交易对的当前余额"""
    from_symbol = get_token_symbol(web3, from_token)
    to_symbol = get_token_symbol(web3, to_token)
    from_dec = get_decimals(web3, from_token)
    to_dec = get_decimals(web3, to_token)
    from_bal = web3.eth.contract(address=from_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** from_dec)
    to_bal = web3.eth.contract(address=to_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** to_dec)
    print(f"\n=== 交易对余额 ===")
    print(f"{from_symbol}余额: {from_bal:.6f}")
    print(f"{to_symbol}余额: {to_bal:.6f}")


def get_expected_output(web3, swap_contract, amount_in, path):
    """获取预期输出数量"""
    try:
        amounts = swap_contract.functions.getAmountsOut(amount_in, path).call()
        return amounts[-1]  # 返回输出数量
    except Exception as e:
        print(f"❌ 无法获取预期价格: {e}")
        return None


def calculate_min_amount(expected_output, slippage_tolerance):
    """计算最小接受数量"""
    min_amount = int(expected_output * (1 - slippage_tolerance))
    return min_amount


# === 授权函数（仅执行一次） ===
def approve_once(web3, token, spender, private_key, amount_wei):
    global AUTHORIZED
    if AUTHORIZED:
        print("✅ 已授权，无需重复操作")
        return True
    account = web3.eth.account.from_key(private_key)
    token_symbol = get_token_symbol(web3, token)
    print(f"🔄 正在授权 {token_symbol}...")
    
    contract = web3.eth.contract(address=token, abi=ERC20_ABI)
    tx = contract.functions.approve(spender, amount_wei).build_transaction({
        "from": account.address,
        "nonce": web3.eth.get_transaction_count(account.address, "latest"),
        "gasPrice": web3.eth.gas_price,
        "gas": 150000
    })
    signed_tx = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, 300)
    
    if receipt.status == 1:
        AUTHORIZED = True
        print("✅ 授权完成")
        return True
    else:
        print("❌ 授权失败")
        return False


# === 核心交易函数 ===
def swap(amount: Decimal, from_token, to_token, private_key):
    if not private_key:
        print("❌ 私钥未配置，请设置PRIVATE_KEY环境变量")
        return None
        
    web3 = Web3(HTTPProvider(RPC_URL))
    if not web3.is_connected():
        print("❌ 连接失败")
        return None

    account = web3.eth.account.from_key(private_key)
    user_addr = account.address
    
    from_symbol = get_token_symbol(web3, from_token)
    to_symbol = get_token_symbol(web3, to_token)
    
    print(f"🎯 使用账户: {user_addr}")
    print(f"🔄 交易方向: {from_symbol} → {to_symbol}")
    print(f"📊 滑点容忍度: {SLIPPAGE_TOLERANCE * 100}%")

    # 获取代币精度
    from_dec = get_decimals(web3, from_token)
    to_dec = get_decimals(web3, to_token)
    
    # 在交易前记录余额
    from_bal_before = web3.eth.contract(address=from_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** from_dec)
    to_bal_before = web3.eth.contract(address=to_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** to_dec)
    
    print(f"\n=== 交易前余额 ===")
    print(f"{from_symbol}余额: {from_bal_before:.6f}")
    print(f"{to_symbol}余额: {to_bal_before:.6f}")

    # 处理金额
    amount_wei = int(amount * (10 ** from_dec))
    print(f"\n💰 兑换金额: {amount} {from_symbol} → {amount_wei} wei")

    # 检查余额
    from_bal_wei = web3.eth.contract(address=from_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call()
    if from_bal_wei < amount_wei:
        print(f"❌ 余额不足: {from_bal_wei} < {amount_wei}")
        return None

    # 仅首次执行授权
    if not approve_once(web3, from_token, SWAP_CONTRACT_ADDRESS, private_key, amount_wei):
        return None

    # 构建交易路径
    path = [from_token, to_token]
    
    # 获取路由器合约
    swap_contract = web3.eth.contract(address=SWAP_CONTRACT_ADDRESS, abi=SWAP_ABI)
    
    # 获取预期输出
    print(f"\n📈 查询预期价格...")
    expected_output = get_expected_output(web3, swap_contract, amount_wei, path)
    
    if expected_output is None:
        print("❌ 无法获取预期价格，交易终止")
        return None
    
    expected_output_normal = expected_output / (10 ** to_dec)
    print(f"✅ 预期获得: {expected_output_normal:.6f} {to_symbol}")
    
    # 计算最小接受数量
    min_acquired = calculate_min_amount(expected_output, SLIPPAGE_TOLERANCE)
    min_acquired_normal = min_acquired / (10 ** to_dec)
    
    print(f"🛡️  最小接受: {min_acquired_normal:.6f} {to_symbol} (基于 {SLIPPAGE_TOLERANCE * 100}% 滑点)")
    
    # 确认交易参数
    print(f"\n⚡ 交易参数确认:")
    print(f"   - 输入金额: {amount} {from_symbol}")
    print(f"   - 预期输出: {expected_output_normal:.6f} {to_symbol}")
    print(f"   - 最小接受: {min_acquired_normal:.6f} {to_symbol}")
    print(f"   - 滑点保护: {SLIPPAGE_TOLERANCE * 100}%")
    
    # 构建交易
    try:
        nonce = web3.eth.get_transaction_count(user_addr, "latest")
        
        print(f"\n🚀 正在发送交易...")
        # 使用 swapExactTokensForTokens 函数
        tx = swap_contract.functions.swapExactTokensForTokens(
            amount_wei,           # amountIn
            min_acquired,         # amountOutMin (基于滑点计算)
            path,                 # path
            user_addr,            # to
            DEADLINE              # deadline
        ).build_transaction({
            "from": user_addr,
            "nonce": nonce,
            "gasPrice": web3.eth.gas_price,
            "gas": 300000,
            "value": 0
        })
        
        signed_tx = web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_hex = web3.to_hex(tx_hash)
        print(f"📤 交易发送: {tx_hex}")

        # 等待结果
        print("⏳ 等待交易确认...")
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, 600)
        if receipt["status"] == 1:
            print(f"✅ 交易成功（区块: {receipt['blockNumber']}）")
            
            # 获取交易后余额
            from_bal_after = web3.eth.contract(address=from_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** from_dec)
            to_bal_after = web3.eth.contract(address=to_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** to_dec)
            
            print(f"\n=== 交易后余额 ===")
            print(f"{from_symbol}余额: {from_bal_after:.6f}")
            print(f"{to_symbol}余额: {to_bal_after:.6f}")
            
            # 正确计算实际获得数量
            actual_gain = to_bal_after - to_bal_before
            
            print(f"\n📊 交易总结:")
            print(f"   - 实际获得: {actual_gain:.6f} {to_symbol}")
            print(f"   - 实际滑点: {((expected_output_normal - actual_gain) / expected_output_normal * 100) if expected_output_normal > 0 else 0:.2f}%")
            print(f"   - Gas 费用: {receipt['gasUsed']} wei")
            
            return tx_hex
        else:
            print(f"❌ 交易失败")
            return None
    except Exception as e:
        print(f"❌ 交易错误: {str(e)}")
        return None


# === 执行入口 ===
if __name__ == "__main__":
    if not PRIVATE_KEY:
        print("❌ 错误: 未设置PRIVATE_KEY环境变量")
        print("请在.env文件中设置PRIVATE_KEY=你的私钥")
        exit(1)
        
    if TRADE_DIRECTION == 1:
        from_t, to_t = TOKENS["WBNB"], TOKENS["USDC"]
        amt = Decimal("0.001")  # 0.001 BNB
    else:
        from_t, to_t = TOKENS["USDC"], TOKENS["WBNB"]
        amt = Decimal("1")  # 1 USDT
        
    print("BSC Swap Bot 启动")
    print("=" * 50)
    swap(amt, from_t, to_t, PRIVATE_KEY)