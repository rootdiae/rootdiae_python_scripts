from web3 import Web3, HTTPProvider
from decimal import Decimal
import time
import os
from dotenv import load_dotenv

# bsc测试网的pancake V3的swap交易，使用Quoter V2获取预期价格，无论正向反向均可以正确获取预期价格并完成交易。

# 加载环境变量
load_dotenv()

# === 核心配置（V3 版本） ===
TRADE_DIRECTION = 0  # 0=反向（CAKE→WBNB），1=正向（WBNB→CAKE）
RPC_URL = "https://bsc-testnet-rpc.publicnode.com"  # BSC 测试网 RPC
PRIVATE_KEY = os.getenv("PRIVATE_KEY")  # 从环境变量读取私钥
SLIPPAGE_TOLERANCE = 0.01  # 1% 滑点容忍度，可调整

# BSC 测试网 PancakeSwap V3 路由器地址（你提供的）
SWAP_CONTRACT_ADDRESS = Web3.to_checksum_address("0x9a489505a00cE272eAa5e07Dba6491314CaE3796")

# BSC 测试网 Quoter V2 官方地址（用于价格查询）
QUOTER_V2_ADDRESS = Web3.to_checksum_address("0xbC203d7f83677c7ed3F7acEc959963E7F4ECC5C2")

# BSC 测试网代币地址（修正为测试网真实地址）
TOKENS = {
    "WBNB": Web3.to_checksum_address("0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd"),  # BSC测试网 WBNB
    "CAKE": Web3.to_checksum_address("0x8d008B313C1d6C7fE2982F62d32Da7507cF43551")   # BSC测试网 CAKE
}

# 代币精度配置
DECIMALS = {"WBNB": 18, "CAKE": 18}

# PancakeSwap V3 费率配置（单位：uint24，可选值：100=0.01%，500=0.05%，3000=0.3%，10000=1%）
FEE_TIER = 2500  # 0.3% 常用费率
DEADLINE = int(time.time() + 600)  # 交易截止时间（10分钟）
AUTHORIZED = False  # 授权状态标记（一次授权后无需重复）
SQRT_PRICE_LIMIT_X96 = 0  # 价格限制（0表示无限制）


# === 合约ABI（PancakeSwap V3 Router） ===
SWAP_ABI = [
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "address", "name": "tokenIn", "type": "address"},
                    {"internalType": "address", "name": "tokenOut", "type": "address"},
                    {"internalType": "uint24", "name": "fee", "type": "uint24"},
                    {"internalType": "address", "name": "recipient", "type": "address"},
                    {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
                    {"internalType": "uint256", "name": "amountOutMinimum", "type": "uint256"},
                    {"internalType": "uint160", "name": "sqrtPriceLimitX96", "type": "uint160"}
                ],
                "internalType": "struct IV3SwapRouter.ExactInputSingleParams",
                "name": "params",
                "type": "tuple"
            }
        ],
        "name": "exactInputSingle",
        "outputs": [{"internalType": "uint256", "name": "amountOut", "type": "uint256"}],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "address", "name": "tokenIn", "type": "address"},
                    {"internalType": "address", "name": "tokenOut", "type": "address"},
                    {"internalType": "uint24", "name": "fee", "type": "uint24"},
                    {"internalType": "address", "name": "recipient", "type": "address"},
                    {"internalType": "uint256", "name": "amountOut", "type": "uint256"},
                    {"internalType": "uint256", "name": "amountInMaximum", "type": "uint256"},
                    {"internalType": "uint160", "name": "sqrtPriceLimitX96", "type": "uint160"}
                ],
                "internalType": "struct IV3SwapRouter.ExactOutputSingleParams",
                "name": "params",
                "type": "tuple"
            }
        ],
        "name": "exactOutputSingle",
        "outputs": [{"internalType": "uint256", "name": "amountIn", "type": "uint256"}],
        "stateMutability": "payable",
        "type": "function"
    }
]

# Quoter V2 完整 ABI（包含所有方法）
QUOTER_V2_ABI = [
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "address", "name": "tokenIn", "type": "address"},
                    {"internalType": "address", "name": "tokenOut", "type": "address"},
                    {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
                    {"internalType": "uint24", "name": "fee", "type": "uint24"},
                    {"internalType": "uint160", "name": "sqrtPriceLimitX96", "type": "uint160"}
                ],
                "internalType": "struct IQuoterV2.QuoteExactInputSingleParams",
                "name": "params",
                "type": "tuple"
            }
        ],
        "name": "quoteExactInputSingle",
        "outputs": [
            {"internalType": "uint256", "name": "amountOut", "type": "uint256"},
            {"internalType": "uint160", "name": "sqrtPriceX96After", "type": "uint160"},
            {"internalType": "uint32", "name": "initializedTicksCrossed", "type": "uint32"},
            {"internalType": "uint256", "name": "gasEstimate", "type": "uint256"}
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "address", "name": "tokenIn", "type": "address"},
                    {"internalType": "address", "name": "tokenOut", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"},
                    {"internalType": "uint24", "name": "fee", "type": "uint24"},
                    {"internalType": "uint160", "name": "sqrtPriceLimitX96", "type": "uint160"}
                ],
                "internalType": "struct IQuoterV2.QuoteExactOutputSingleParams",
                "name": "params",
                "type": "tuple"
            }
        ],
        "name": "quoteExactOutputSingle",
        "outputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "uint160", "name": "sqrtPriceX96After", "type": "uint160"},
            {"internalType": "uint32", "name": "initializedTicksCrossed", "type": "uint32"},
            {"internalType": "uint256", "name": "gasEstimate", "type": "uint256"}
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

# ERC20 代币 ABI（不变）
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
    except Exception as e:
        print(f"⚠️ 获取代币符号失败: {e}")
        return "Unknown"

def get_decimals(web3, token):
    """获取代币精度"""
    try:
        return web3.eth.contract(address=token, abi=ERC20_ABI).functions.decimals().call()
    except Exception as e:
        print(f"❌ 获取代币精度失败: {e}")
        raise

def print_balances(web3, from_token, to_token, user_addr):
    """打印交易对的当前余额"""
    from_symbol = get_token_symbol(web3, from_token)
    to_symbol = get_token_symbol(web3, to_token)
    from_dec = get_decimals(web3, from_token)
    to_dec = get_decimals(web3, to_token)
    
    try:
        from_bal = web3.eth.contract(address=from_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** from_dec)
        to_bal = web3.eth.contract(address=to_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** to_dec)
        print(f"\n=== 交易对余额 ===")
        print(f"{from_symbol}余额: {from_bal:.6f}")
        print(f"{to_symbol}余额: {to_bal:.6f}")
        return to_bal  # 返回输出代币的余额，用于后续计算实际获得数量
    except Exception as e:
        print(f"❌ 获取余额失败: {e}")
        return 0

def is_address_less(addr1: str, addr2: str) -> bool:
    """比较两个地址的字典序（小写字符串比较）"""
    return addr1.lower() < addr2.lower()

def get_expected_output(web3, amount_in, from_token, to_token, from_dec, to_dec):
    """
    使用 Quoter V2 获取预期输出数量（V3 专用方法）
    
    Args:
        web3: Web3 实例
        amount_in: 输入金额（wei）
        from_token: 输入代币地址
        to_token: 输出代币地址
        from_dec: 输入代币精度
        to_dec: 输出代币精度
    
    Returns:
        amount_out: 预期输出数量（wei），失败返回 None
    """
    try:
        # 初始化 Quoter V2 合约
        quoter_contract = web3.eth.contract(
            address=QUOTER_V2_ADDRESS,
            abi=QUOTER_V2_ABI
        )
        
        # 校验 Quoter 合约存在性
        if len(web3.eth.get_code(QUOTER_V2_ADDRESS)) == 0:
            print("❌ Quoter V2 合约不存在")
            return None
        
        from_symbol = get_token_symbol(web3, from_token)
        to_symbol = get_token_symbol(web3, to_token)
        
        print(f"🔍 查询参数：{amount_in/(10**from_dec):.6f} {from_symbol} → {to_symbol}")
        
        # 根据地址顺序选择合适的查询方法
        if is_address_less(from_token, to_token):
            # 正向查询：tokenIn < tokenOut，使用 quoteExactInputSingle
            print(f"  使用 quoteExactInputSingle（正向查询）")
            
            # 构建 Quoter V2 调用参数
            quote_params = (
                from_token,               # tokenIn
                to_token,                 # tokenOut
                amount_in,                # 输入金额（wei）
                FEE_TIER,                 # 费率
                SQRT_PRICE_LIMIT_X96      # 价格限制
            )
            
            # 调用 Quoter V2 获取预期价格
            start_time = time.time()
            amount_out_wei, sqrt_price, ticks_crossed, gas_estimate = quoter_contract.functions.quoteExactInputSingle(
                quote_params
            ).call()
            query_time = round((time.time() - start_time) * 1000, 2)
            
        else:
            # 反向查询：tokenIn > tokenOut，使用 quoteExactOutputSingle
            print(f"  使用 quoteExactOutputSingle（反向查询）")
            
            # 对于反向查询，我们直接使用 quoteExactOutputSingle
            # 注意：这里我们交换了tokenIn和tokenOut的位置
            reverse_quote_params = (
                to_token,           # tokenIn（交换位置）
                from_token,         # tokenOut（交换位置）
                amount_in,          # 输出金额（我们想要得到的输出代币数量）
                FEE_TIER,           # 费率
                SQRT_PRICE_LIMIT_X96  # 价格限制
            )
            
            start_time = time.time()
            # 调用 quoteExactOutputSingle 获取需要的输入金额
            amount_in_required, sqrt_price, ticks_crossed, gas_estimate = quoter_contract.functions.quoteExactOutputSingle(
                reverse_quote_params
            ).call()
            query_time = round((time.time() - start_time) * 1000, 2)
            
            # 对于反向查询，我们需要计算实际输出金额
            amount_out_wei = amount_in_required
            
            print(f"   反向查询结果：需要 {amount_in_required/(10**to_dec):.6f} {to_symbol} 才能得到 {amount_in/(10**from_dec):.6f} {from_symbol}")
        
        # 转换输出金额为可读格式
        amount_out_normal = amount_out_wei / (10 ** to_dec)
        
        print(f"✅ Quoter V2 查询成功！")
        print(f"   预期输出：{amount_out_normal:.6f} {to_symbol}")
        print(f"   查询耗时：{query_time}ms")
        print(f"   穿越Tick数：{ticks_crossed} | 燃气估算：{gas_estimate} gas")
        
        return amount_out_wei
        
    except Exception as e:
        print(f"❌ Quoter V2 查询失败: {str(e)[:200]}")
        return None

def calculate_min_amount(expected_output, slippage_tolerance):
    """计算最小接受数量（考虑滑点）"""
    min_amount = int(expected_output * (1 - slippage_tolerance))
    # 确保最小数量不为0
    return max(min_amount, 1)


# === 授权函数（仅执行一次） ===
def approve_once(web3, token, spender, private_key, amount_wei):
    global AUTHORIZED
    if AUTHORIZED:
        print("✅ 已授权，无需重复操作")
        return True
    
    account = web3.eth.account.from_key(private_key)
    token_symbol = get_token_symbol(web3, token)
    print(f"🔄 正在授权 {token_symbol} 给路由器...")
    
    try:
        contract = web3.eth.contract(address=token, abi=ERC20_ABI)
        # 授权最大金额（或具体金额）
        tx = contract.functions.approve(spender, amount_wei).build_transaction({
            "from": account.address,
            "nonce": web3.eth.get_transaction_count(account.address, "latest"),
            "gasPrice": web3.eth.gas_price,
            "gas": 150000  # 授权交易gas限制
        })
        
        # 签名并发送交易
        signed_tx = web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        
        if receipt.status == 1:
            AUTHORIZED = True
            print(f"✅ 授权完成！交易哈希: {web3.to_hex(tx_hash)}")
            return True
        else:
            print("❌ 授权失败（交易状态异常）")
            return False
    except Exception as e:
        print(f"❌ 授权错误: {str(e)}")
        return False


# === 核心交易函数（V3 版本） ===
def swap(amount: Decimal, from_token, to_token, private_key):
    if not private_key:
        print("❌ 私钥未配置，请设置PRIVATE_KEY环境变量")
        return None
        
    # 初始化web3连接
    web3 = Web3(HTTPProvider(RPC_URL))
    if not web3.is_connected():
        print("❌ BSC测试网连接失败，请检查RPC地址")
        return None

    account = web3.eth.account.from_key(private_key)
    user_addr = account.address
    
    # 获取代币信息
    from_symbol = get_token_symbol(web3, from_token)
    to_symbol = get_token_symbol(web3, to_token)
    
    print(f"🎯 使用账户: {user_addr}")
    print(f"🔄 交易方向: {from_symbol} → {to_symbol}")
    print(f"📊 配置信息: 滑点={SLIPPAGE_TOLERANCE * 100}%, 费率={FEE_TIER/10000}%")

    # 获取代币精度
    from_dec = get_decimals(web3, from_token)
    to_dec = get_decimals(web3, to_token)
    
    # 打印交易前余额并记录输出代币的初始余额
    print(f"\n=== 交易前余额 ===")
    from_bal_before = web3.eth.contract(address=from_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** from_dec)
    to_bal_before = web3.eth.contract(address=to_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** to_dec)
    print(f"{from_symbol}余额: {from_bal_before:.6f}")
    print(f"{to_symbol}余额: {to_bal_before:.6f}")
    
    # 处理金额（转换为wei）
    amount_wei = int(amount * (10 ** from_dec))
    print(f"\n💰 兑换金额: {amount} {from_symbol} → {amount_wei} wei")

    # 检查余额
    try:
        from_bal_wei = web3.eth.contract(address=from_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call()
        if from_bal_wei < amount_wei:
            print(f"❌ 余额不足: 可用 {from_bal_wei/(10**from_dec):.6f} {from_symbol} < 需要 {amount} {from_symbol}")
            return None
    except Exception as e:
        print(f"❌ 余额检查失败: {e}")
        return None

    # 仅首次执行授权（授权金额为实际交易金额）
    if not approve_once(web3, from_token, SWAP_CONTRACT_ADDRESS, private_key, amount_wei):
        print("❌ 授权失败，交易终止")
        return None

    # 获取V3路由器合约
    swap_contract = web3.eth.contract(address=SWAP_CONTRACT_ADDRESS, abi=SWAP_ABI)
    
    # 使用 Quoter V2 获取预期输出
    print(f"\n📈 使用 Quoter V2 查询预期价格...")
    expected_output = get_expected_output(web3, amount_wei, from_token, to_token, from_dec, to_dec)
    
    if expected_output is None:
        print("❌ 无法获取预期价格，交易终止")
        return None
    
    expected_output_normal = expected_output / (10 ** to_dec)
    print(f"✅ 预期获得: {expected_output_normal:.6f} {to_symbol}")
    
    # 计算最小接受数量（滑点保护）
    min_acquired = calculate_min_amount(expected_output, SLIPPAGE_TOLERANCE)
    min_acquired_normal = min_acquired / (10 ** to_dec)
    
    print(f"🛡️  最小接受: {min_acquired_normal:.6f} {to_symbol} (基于 {SLIPPAGE_TOLERANCE * 100}% 滑点)")
    
    # 构建V3交易参数（ExactInputSingle）
    print(f"\n⚡ 正在构建V3交易...")
    try:
        nonce = web3.eth.get_transaction_count(user_addr, "latest")
        
        # V3 ExactInputSingle 参数
        swap_params = {
            "tokenIn": from_token,
            "tokenOut": to_token,
            "fee": FEE_TIER,
            "recipient": user_addr,
            "amountIn": amount_wei,
            "amountOutMinimum": min_acquired,
            "sqrtPriceLimitX96": SQRT_PRICE_LIMIT_X96
        }
        
        # 构建交易
        tx = swap_contract.functions.exactInputSingle(swap_params).build_transaction({
            "from": user_addr,
            "nonce": nonce,
            "gasPrice": web3.eth.gas_price,
            "gas": 300000,  # V3交易gas限制（比V2略高）
            "value": 0  # ERC20代币交易无需ETH
        })
        
        # 签名交易
        signed_tx = web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_hex = web3.to_hex(tx_hash)
        print(f"📤 交易已发送: {tx_hex}")
        print("⏳ 等待交易确认...")

        # 等待交易确认
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
        if receipt["status"] == 1:
            print(f"✅ 交易成功！区块号: {receipt['blockNumber']}")
            
            # 获取交易后余额
            from_bal_after = web3.eth.contract(address=from_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** from_dec)
            to_bal_after = web3.eth.contract(address=to_token, abi=ERC20_ABI).functions.balanceOf(user_addr).call() / (10 ** to_dec)
            
            print(f"\n=== 交易后余额 ===")
            print(f"{from_symbol}余额: {from_bal_after:.6f}")
            print(f"{to_symbol}余额: {to_bal_after:.6f}")
            
            # 修正：正确计算实际获得数量（交易后余额 - 交易前余额）
            actual_gain = to_bal_after - to_bal_before
            
            # 修正：正确计算实际滑点
            if expected_output_normal > 0:
                actual_slippage = ((expected_output_normal - actual_gain) / expected_output_normal) * 100
            else:
                actual_slippage = 0
            
            print(f"\n📊 交易总结:")
            print(f"   - 实际获得: {actual_gain:.6f} {to_symbol}")
            print(f"   - 预期获得: {expected_output_normal:.6f} {to_symbol}")
            print(f"   - 实际滑点: {actual_slippage:.2f}%")
            print(f"   - Gas使用量: {receipt['gasUsed']}")
            print(f"   - 交易哈希: {tx_hex}")
            
            return tx_hex
        else:
            print(f"❌ 交易失败（状态码: {receipt['status']}）")
            return None
    except Exception as e:
        print(f"❌ 交易错误: {str(e)}")
        return None


# === 执行入口 ===
if __name__ == "__main__":
    if not PRIVATE_KEY:
        print("❌ 错误: 未设置PRIVATE_KEY环境变量")
        print("请在.env文件中设置PRIVATE_KEY=你的BSC测试网私钥")
        exit(1)
        
    # 根据交易方向选择代币对
    if TRADE_DIRECTION == 1:
        from_t, to_t = TOKENS["WBNB"], TOKENS["CAKE"]
        amt = Decimal("0.001")  # 正向交易：0.001 WBNB → CAKE
    else:
        from_t, to_t = TOKENS["CAKE"], TOKENS["WBNB"]
        amt = Decimal("0.5")  # 反向交易：1 CAKE → WBNB
        
    print("=" * 60)
    print("🎯 PancakeSwap V3 BSC测试网 Swap Bot (Quoter V2 价格查询)")
    print("=" * 60)
    swap(amt, from_t, to_t, PRIVATE_KEY)