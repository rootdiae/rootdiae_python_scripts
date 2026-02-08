import logging
import os
import time
import json
from decimal import Decimal
from web3 import Web3, HTTPProvider
from dotenv import load_dotenv
import requests
from typing import Dict, List, Optional, Tuple

#适配48Club Puissant Builder版本，此脚本用于测试revert功能，可以设置#"revertingTxHashes": []参数来只允许swap交易revert

# 加载环境变量
load_dotenv()

# === 日志配置 ===
def setup_logging():
    """配置日志系统，同时输出到控制台和文件"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # 避免重复添加handler
    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
    
    # 格式化器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    
    # 控制台handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 文件handler
    file_handler = logging.FileHandler('bsc_swap_bundle_48club.log', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

# 初始化日志
logger = setup_logging()

# === 核心配置（BSC主网版本） ===
TRADE_DIRECTION = 0  # 0=(USDT→WBNB），1=(WBNB→USDT)
RPC_URLS = [
        "https://bsc-dataseed.bnbchain.org",
        "https://wallet.okex.org/fullnode/bsc/discover/rpc",
        "https://bsc-mainnet.public.blastapi.io",
        "https://binance.llamarpc.com",
        "https://bsc.drpc.org",
        "https://bsc-rpc.publicnode.com"
]  # BSC主网多节点RPC，用于容错
PUISSANT_RPC_URL = "https://puissant-builder.48.club/"  # 48Club Puissant Builder RPC
PRIVATE_KEY = os.getenv("PRIVATE_KEY")  # 从环境变量读取私钥
SLIPPAGE_TOLERANCE = -0.5  # 50% 滑点容忍度

# BSC主网 PancakeSwap V3 路由器地址
SWAP_CONTRACT_ADDRESS = Web3.to_checksum_address("0x13f4EA83D0bd40E75C8222255bc855a974568Dd4")

# BSC主网 Quoter V2 官方地址
QUOTER_V2_ADDRESS = Web3.to_checksum_address("0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997")

# 48Club的Builder Control EOA地址
PUISSANT_BUILDER_EOA = Web3.to_checksum_address("0x4848489f0b2BEdd788c696e2D79b6b69D7484848")  # 48Club Builder Control EOA

# BSC主网代币地址
TOKENS = {
    "WBNB": Web3.to_checksum_address("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),  # BSC主网 WBNB
    "USDT": Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955")   # BSC主网 USDT
}

# 代币精度配置
DECIMALS = {"WBNB": 18, "USDT": 18}  

# PancakeSwap V3 费率配置
FEE_TIER = 100  # 0.25% 池子费率
DEADLINE = int(time.time() + 600)  # 交易截止时间（10分钟）
PAYMENT_AMOUNT_BNB = Decimal("0.00000001")  # 支付给48Club Builder Control EOA的BNB金额
MIN_GAS_PRICE = Web3.to_wei(0.05, 'gwei')  # BSC验证器要求的最低gas价格

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

# ERC20 代币 ABI
ERC20_ABI = [
    {"constant": False, "inputs": [{"name": "_spender", "type": "address"}, {"name": "_value", "type": "uint256"}],
     "name": "approve", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "account", "type": "address"}], "name": "balanceOf",
     "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}],
     "name": "allowance", "outputs": [{"name": "", "type": "uint256"}], "type": "function"}  # 添加这一行
]

# === Web3连接管理 ===
class Web3Manager:
    """管理Web3连接，支持多节点轮询"""
    
    def __init__(self, rpc_urls: List[str]):
        self.rpc_urls = rpc_urls
        self.current_index = 0
        self.web3 = None
        self._connect()
    
    def _connect(self) -> bool:
        """连接到可用的RPC节点"""
        for _ in range(len(self.rpc_urls)):
            try:
                url = self.rpc_urls[self.current_index]
                logger.info(f"尝试连接RPC节点: {url}")
                
                web3 = Web3(HTTPProvider(url, request_kwargs={'timeout': 30}))
                
                # 检查连接状态
                if web3.is_connected():
                    # 移除了POA中间件注入，对于交易操作不需要
                    self.web3 = web3
                    logger.info(f"成功连接到RPC节点: {url}")
                    logger.info(f"当前区块高度: {web3.eth.block_number}")
                    return True
                else:
                    logger.warning(f"无法连接到RPC节点: {url}")
                    
            except Exception as e:
                logger.warning(f"连接RPC节点失败: {self.rpc_urls[self.current_index]}, 错误: {str(e)[:200]}")
            
            # 轮询到下一个节点
            self.current_index = (self.current_index + 1) % len(self.rpc_urls)
            time.sleep(1)  # 短暂延迟
        
        logger.error("所有RPC节点连接失败")
        return False
    
    def get_web3(self):
        """获取Web3实例，如果当前连接失效则尝试重连"""
        if self.web3 is None or not self.web3.is_connected():
            logger.warning("Web3连接失效，尝试重新连接...")
            if not self._connect():
                raise Exception("无法建立Web3连接")
        return self.web3

# 初始化Web3管理器
web3_manager = Web3Manager(RPC_URLS)

# === 核心工具函数 ===
def get_token_symbol(web3, token_address: str) -> str:
    """获取代币符号 - 从配置中获取"""
    # 通过地址反向查找代币符号
    for symbol, address in TOKENS.items():
        if address.lower() == token_address.lower():
            return symbol
    logger.warning(f"未在配置中找到代币符号，地址: {token_address}")
    return "Unknown"

def get_decimals(web3, token_address: str) -> int:
    """获取代币精度 - 从配置中获取"""
    # 通过地址反向查找代币精度
    for symbol, address in TOKENS.items():
        if address.lower() == token_address.lower():
            if symbol in DECIMALS:
                return DECIMALS[symbol]
            else:
                logger.warning(f"未在DECIMALS配置中找到代币精度，代币: {symbol}")
                return 18  # 默认返回18位精度
    logger.warning(f"未在配置中找到代币精度，地址: {token_address}，使用默认精度18")
    return 18  # 默认返回18位精度

def is_address_less(addr1: str, addr2: str) -> bool:
    """比较两个地址的字典序"""
    return addr1.lower() < addr2.lower()

def get_expected_output(web3, amount_in: int, from_token: str, to_token: str, 
                       from_dec: int, to_dec: int) -> Optional[int]:
    """
    使用 Quoter V2 获取预期输出数量
    """
    try:
        quoter_contract = web3.eth.contract(
            address=QUOTER_V2_ADDRESS,
            abi=QUOTER_V2_ABI
        )
        
        # 检查Quoter合约是否存在
        if len(web3.eth.get_code(QUOTER_V2_ADDRESS)) == 0:
            logger.error("Quoter V2 合约不存在")
            return None
        
        from_symbol = get_token_symbol(web3, from_token)
        to_symbol = get_token_symbol(web3, to_token)
        
        logger.info(f"查询参数：{amount_in/(10**from_dec):.6f} {from_symbol} → {to_symbol}")
        
        # 根据地址顺序选择查询方法
        if is_address_less(from_token, to_token):
            logger.info("使用 quoteExactInputSingle（正向查询）")
            
            quote_params = (
                from_token,               # tokenIn
                to_token,                 # tokenOut
                amount_in,                # 输入金额
                FEE_TIER,                 # 费率
                0                         # 价格限制
            )
            
            start_time = time.time()
            amount_out_wei, sqrt_price, ticks_crossed, gas_estimate = quoter_contract.functions.quoteExactInputSingle(
                quote_params
            ).call()
            query_time = round((time.time() - start_time) * 1000, 2)
            
        else:
            logger.info("使用 quoteExactOutputSingle（反向查询）")
            
            reverse_quote_params = (
                to_token,           # tokenIn
                from_token,         # tokenOut  
                amount_in,          # 输出金额
                FEE_TIER,           # 费率
                0                   # 价格限制
            )
            
            start_time = time.time()
            amount_in_required, sqrt_price, ticks_crossed, gas_estimate = quoter_contract.functions.quoteExactOutputSingle(
                reverse_quote_params
            ).call()
            query_time = round((time.time() - start_time) * 1000, 2)
            
            amount_out_wei = amount_in_required
            logger.info(f"反向查询结果：需要 {amount_in_required/(10**to_dec):.6f} {to_symbol} 才能得到 {amount_in/(10**from_dec):.6f} {from_symbol}")
        
        amount_out_normal = amount_out_wei / (10 ** to_dec)
        
        logger.info(f"Quoter V2 查询成功: 预期输出 {amount_out_normal:.6f} {to_symbol}")
        logger.info(f"查询耗时: {query_time}ms, 穿越Tick数: {ticks_crossed}, Gas估算: {gas_estimate}")
        
        return amount_out_wei
        
    except Exception as e:
        logger.error(f"Quoter V2 查询失败: {str(e)}")
        return None

def calculate_min_amount(expected_output: int, slippage_tolerance: float) -> int:
    """计算最小接受数量（考虑滑点）"""
    min_amount = int(expected_output * (1 - slippage_tolerance))
    return max(min_amount, 1)

def approve_token(web3, token: str, spender: str, private_key: str, amount_wei: int) -> bool:
    """
    授权代币给路由器
    返回值：True=实际发送了授权交易（消耗Nonce），False=未发送授权交易（已有足够授权/授权失败）
    """
    account = web3.eth.account.from_key(private_key)
    token_symbol = get_token_symbol(web3, token)
    logger.info(f"正在授权 {token_symbol} 给路由器...")
    
    try:
        contract = web3.eth.contract(address=token, abi=ERC20_ABI)
        
        # 检查合约是否支持allowance函数
        try:
            # 检查当前授权额度
            current_allowance = contract.functions.allowance(account.address, spender).call()
            if current_allowance >= amount_wei:
                logger.info(f"已有足够授权额度: {current_allowance} (需要: {amount_wei})，无需重复授权")
                return False  # 未发送交易，不消耗Nonce
            else:
                logger.info(f"当前授权额度不足: {current_allowance} < {amount_wei}，需要授权")
        except Exception as e:
            logger.warning(f"无法查询当前授权额度，继续执行授权: {str(e)}")
        
        # 构建授权交易
        tx = contract.functions.approve(spender, amount_wei).build_transaction({
            "from": account.address,
            "nonce": web3.eth.get_transaction_count(account.address),
            "gasPrice": max(web3.eth.gas_price, MIN_GAS_PRICE),
            "gas": 100000,
        })
        
        # 签名并发送
        signed_tx = web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        logger.info(f"授权交易已发送: {web3.to_hex(tx_hash)}")
        
        # 等待确认
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        if receipt.status == 1:
            logger.info("授权成功（已消耗1个Nonce）")
            
            # 验证授权是否成功
            try:
                new_allowance = contract.functions.allowance(account.address, spender).call()
                logger.info(f"授权后额度: {new_allowance}")
            except:
                logger.info("无法验证授权后额度")
                
            return True  # 实际发送了交易，消耗了Nonce
        else:
            logger.error("授权失败（交易已发送但执行失败）")
            return False  # 交易失败，虽消耗Nonce但逻辑上视为未授权成功
            
    except Exception as e:
        logger.error(f"授权错误: {str(e)}")
        return False  # 未发送交易，不消耗Nonce

# === Bundle交易构建函数 ===
def build_payment_transaction(web3, private_key: str, nonce: int) -> Dict:
    """
    构建支付给48Club Builder Control EOA的交易
    """
    account = web3.eth.account.from_key(private_key)
    
    # 获取当前gas价格
    gas_price = max(web3.eth.gas_price, MIN_GAS_PRICE)
    
    # 构建支付交易
    payment_tx = {
        'nonce': nonce,
        'to': PUISSANT_BUILDER_EOA, 
        'value': Web3.to_wei(PAYMENT_AMOUNT_BNB, 'ether'),
        'gas': 21000,  # 标准ETH转账gas limit
        'gasPrice': gas_price,
        'chainId': 56,  # BSC主网chainId
    }
    
    logger.info(f"构建支付交易: 支付 {PAYMENT_AMOUNT_BNB} BNB 到 48Club Builder Control EOA")
    return payment_tx

def build_swap_transaction(web3, amount_wei: int, from_token: str, to_token: str, 
                          private_key: str, nonce: int, expected_output: int) -> Optional[Dict]:
    """
    构建swap交易
    """
    account = web3.eth.account.from_key(private_key)
    
    try:
        from_dec = get_decimals(web3, from_token)
        to_dec = get_decimals(web3, to_token)
        
        # 计算最小接受数量
        min_acquired = calculate_min_amount(expected_output, SLIPPAGE_TOLERANCE)
        
        # 构建swap参数
        swap_params = {
            "tokenIn": from_token,
            "tokenOut": to_token,
            "fee": FEE_TIER,
            "recipient": account.address,
            "amountIn": amount_wei,
            "amountOutMinimum": min_acquired,
            "sqrtPriceLimitX96": 0
        }
        
        # 获取swap合约
        swap_contract = web3.eth.contract(address=SWAP_CONTRACT_ADDRESS, abi=SWAP_ABI)
        
        # 估算gas
        #gas_estimate = swap_contract.functions.exactInputSingle(swap_params).estimate_gas({
            #'from': account.address,
            #'value': 0
        #})
        
        # 构建交易
        swap_tx = swap_contract.functions.exactInputSingle(swap_params).build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gasPrice': max(web3.eth.gas_price, MIN_GAS_PRICE),
            'gas': 1000000, #int(gas_estimate * 1.2),  # 增加20%缓冲
            'value': 0,
        })
        
        from_symbol = get_token_symbol(web3, from_token)
        to_symbol = get_token_symbol(web3, to_token)
        logger.info(f"构建swap交易: {amount_wei/(10**from_dec):.6f} {from_symbol} → {min_acquired/(10**to_dec):.18f} {to_symbol}，最小接受量(基于 {SLIPPAGE_TOLERANCE * 100}% 滑点)")  # 临时修改，需改回为.6f
        
        return swap_tx
        
    except Exception as e:
        logger.error(f"构建swap交易失败: {str(e)}")
        return None

def sign_transaction(web3, transaction: Dict, private_key: str) -> Tuple[str, str]:
    """签名交易并返回原始交易数据和交易哈希"""
    signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
    tx_hash = web3.to_hex(signed_tx.hash)  # 计算交易哈希
    raw_tx = Web3.to_hex(signed_tx.raw_transaction)  # 原始交易数据
    return raw_tx, tx_hash

def send_bundle_to_48club(signed_transactions: List[str], current_block_number: int, 
                         reverting_tx_hashes: List[str] = None) -> Optional[str]:
    """
    发送bundle到48Club Puissant Builder
    
    Args:
        signed_transactions: 已签名的原始交易列表
        current_block_number: 当前区块号
        reverting_tx_hashes: 允许revert的交易哈希列表
    
    Returns:
        bundle_hash: 如果成功返回bundle hash，失败返回None
    """
    try:
        # 获取当前时间戳（秒）
        current_timestamp = int(time.time())
        
        # 构建bundle请求
        bundle_data = {
            "txs": signed_transactions,  # 已签名的原始交易列表
            "maxBlockNumber": current_block_number + 100,  # 该 bundle 有效的最大区块号，默认当前区块号 + 100
            "maxTimestamp": current_timestamp + 300,  # 期望 bundle 有效的最大 Unix 秒级时间戳。5分钟有效期。
        }
        
        # 添加允许revert的交易哈希（如果有）
        if reverting_tx_hashes:
            bundle_data["revertingTxHashes"] = reverting_tx_hashes
        
        # 构建JSON-RPC请求
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendBundle",
            "params": [bundle_data]  # 注意：params是包含bundle_data的数组
        }
        
        logger.info(f"正在发送bundle到48Club Puissant Builder...")
        logger.info(f"Bundle参数: maxBlockNumber={bundle_data['maxBlockNumber']}, "
                   f"maxTimestamp={bundle_data['maxTimestamp']}, "
                   f"交易数量={len(signed_transactions)}")
        
        # 如果有允许revert的交易，打印相关信息
        if reverting_tx_hashes:
            logger.info(f"允许revert的交易哈希: {reverting_tx_hashes}")
        
        # 发送请求到48Club Puissant Builder
        response = requests.post(
            PUISSANT_RPC_URL,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        # 记录原始响应用于调试
        logger.debug(f"48Club Puissant Builder响应状态码: {response.status_code}")
        logger.debug(f"48Club Puissant Builder响应内容: {response.text}")
        
        response_data = response.json()
        
        if 'result' in response_data:
            bundle_hash = response_data['result']
            logger.info(f"Bundle发送成功! Bundle Hash: {bundle_hash}")
            return bundle_hash
        else:
            error_code = response_data.get('error', {}).get('code', 'Unknown')
            error_msg = response_data.get('error', {}).get('message', 'Unknown error')
            logger.error(f"Bundle发送失败: 错误码={error_code}, 错误信息={error_msg}")
            return None
            
    except requests.exceptions.Timeout:
        logger.error("发送bundle到48Club Puissant Builder超时")
        return None
    except requests.exceptions.ConnectionError:
        logger.error("连接48Club Puissant Builder失败，请检查网络连接")
        return None
    except Exception as e:
        logger.error(f"发送bundle到48Club Puissant Builder失败: {str(e)}")
        return None

# === 主交易函数 ===
def execute_swap_with_bundle(amount: Decimal, from_token: str, to_token: str, private_key: str) -> Optional[str]:
    """
    执行包含付费交易的bundle swap，并计算实际交易结果
    """
    if not private_key:
        logger.error("私钥未配置")
        return None
        
    try:
        web3 = web3_manager.get_web3()
        account = web3.eth.account.from_key(private_key)
        user_addr = account.address
        
        # 获取代币符号用于日志
        from_symbol = get_token_symbol(web3, from_token)
        to_symbol = get_token_symbol(web3, to_token)
        
        # === 交易前余额查询 ===
        logger.info("=" * 50)
        logger.info("交易前余额查询")
        logger.info("=" * 50)
        
        # 获取初始nonce和区块号
        current_nonce = web3.eth.get_transaction_count(user_addr)
        current_block_number = web3.eth.block_number
        
        # 查询BNB余额
        bnb_balance_before = web3.eth.get_balance(user_addr)
        bnb_balance_before_normal = web3.from_wei(bnb_balance_before, 'ether')
        
        # 查询from_token余额
        from_token_contract = web3.eth.contract(address=from_token, abi=ERC20_ABI)
        from_token_balance_before = from_token_contract.functions.balanceOf(user_addr).call()
        from_dec = get_decimals(web3, from_token)
        from_token_balance_before_normal = from_token_balance_before / (10 ** from_dec)
        
        # 查询to_token余额
        to_token_contract = web3.eth.contract(address=to_token, abi=ERC20_ABI)
        to_token_balance_before = to_token_contract.functions.balanceOf(user_addr).call()
        to_dec = get_decimals(web3, to_token)
        to_token_balance_before_normal = to_token_balance_before / (10 ** to_dec)
        
        # 记录交易前余额
        logger.info(f"BNB余额: {bnb_balance_before_normal:.8f} BNB")
        logger.info(f"{from_symbol}余额: {from_token_balance_before_normal:.8f} {from_symbol}")
        logger.info(f"{to_symbol}余额: {to_token_balance_before_normal:.8f} {to_symbol}")
        
        logger.info(f"Nonce: {current_nonce}, 当前区块号: {current_block_number}")
        
        # 检查BNB余额（用于支付交易）
        payment_amount_wei = Web3.to_wei(PAYMENT_AMOUNT_BNB, 'ether')
        if bnb_balance_before < payment_amount_wei:
            logger.error(f"BNB余额不足: 需要 {PAYMENT_AMOUNT_BNB} BNB, 当前 {bnb_balance_before_normal:.8f} BNB")
            return None
        
        # 检查代币余额
        amount_wei = int(amount * (10 ** from_dec))
        if from_token_balance_before < amount_wei:
            logger.error(f"{from_symbol}余额不足: 需要 {amount:.6f} {from_symbol}, 当前 {from_token_balance_before_normal:.6f} {from_symbol}")
            return None
        
        # 执行授权并判断是否消耗了Nonce
        approve_executed = approve_token(web3, from_token, SWAP_CONTRACT_ADDRESS, private_key, amount_wei)
        if approve_executed:
            # 授权交易消耗了1个Nonce，更新基准Nonce
            current_nonce += 1
            logger.info(f"授权交易消耗了1个Nonce，更新后Nonce: {current_nonce}")
        elif not approve_executed:
            # 未执行授权（已有足够额度），Nonce保持不变
            logger.info(f"未执行授权交易，Nonce仍为: {current_nonce}")
        
        # 授权失败直接返回（原逻辑保留）
        if not approve_executed and not approve_token:
            return None
        
        # 获取预期输出用于后续计算实际滑点
        expected_output = get_expected_output(web3, amount_wei, from_token, to_token, from_dec, to_dec)
        if expected_output is None:
            return None
        
        expected_output_normal = expected_output / (10 ** to_dec)
        logger.info(f"预期输出: {expected_output_normal:.18f} {to_symbol}")  #临时修改，需改回为.6f
        
        # 构建swap交易（使用Nonce，传入已查询的expected_output）
        swap_tx = build_swap_transaction(web3, amount_wei, from_token, to_token, private_key, current_nonce, expected_output)
        
        # 构建支付交易（使用更新后的Nonce+1）
        payment_tx = build_payment_transaction(web3, private_key, current_nonce + 1)
        if not swap_tx:
            return None
        
        # 签名交易，获取原始交易数据和交易哈希
        raw_swap_tx, swap_tx_hash = sign_transaction(web3, swap_tx, private_key)
        raw_payment_tx, payment_tx_hash = sign_transaction(web3, payment_tx, private_key)

        logger.info(f"Swap交易哈希: {swap_tx_hash}")
        logger.info(f"支付交易哈希: {payment_tx_hash}")        

        bundle_hash = send_bundle_to_48club(
            [ raw_swap_tx,raw_payment_tx],  # 支付交易在前，swap交易在后
            current_block_number,
            reverting_tx_hashes=[swap_tx_hash]  # 只允许swap交易revert
        )

        if bundle_hash:
            logger.info(f"Bundle交易提交成功! Bundle Hash: {bundle_hash}")
            
            # === 等待交易确认 ===
            logger.info("等待交易确认...")
            time.sleep(30)  # 等待30秒让交易有足够时间被确认
            
            # === 交易后余额查询 ===
            logger.info("=" * 50)
            logger.info("交易后余额查询")
            logger.info("=" * 50)
            
            # 查询交易后余额
            bnb_balance_after = web3.eth.get_balance(user_addr)
            bnb_balance_after_normal = web3.from_wei(bnb_balance_after, 'ether')
            
            from_token_balance_after = from_token_contract.functions.balanceOf(user_addr).call()
            from_token_balance_after_normal = from_token_balance_after / (10 ** from_dec)
            
            to_token_balance_after = to_token_contract.functions.balanceOf(user_addr).call()
            to_token_balance_after_normal = to_token_balance_after / (10 ** to_dec)
            
            # 记录交易后余额
            logger.info(f"BNB余额: {bnb_balance_after_normal:.8f} BNB")
            logger.info(f"{from_symbol}余额: {from_token_balance_after_normal:.8f} {from_symbol}")
            logger.info(f"{to_symbol}余额: {to_token_balance_after_normal:.8f} {to_symbol}")
            
            # === 计算实际交易结果 ===
            logger.info("=" * 50)
            logger.info("实际交易结果分析")
            logger.info("=" * 50)
            
            # 计算实际交易获得数量
            actual_to_token_received = to_token_balance_after - to_token_balance_before
            actual_to_token_received_normal = actual_to_token_received / (10 ** to_dec)
            
            # 计算实际from_token减少数量
            actual_from_token_spent = from_token_balance_before - from_token_balance_after
            actual_from_token_spent_normal = actual_from_token_spent / (10 ** from_dec)
            
            # 计算实际BNB减少数量
            actual_bnb_spent = bnb_balance_before - bnb_balance_after
            actual_bnb_spent_normal = web3.from_wei(actual_bnb_spent, 'ether')
            
            # 计算实际滑点
            if expected_output > 0:
                actual_slippage = ((expected_output - actual_to_token_received) / expected_output) * 100
            else:
                actual_slippage = 0
            
            # 记录实际交易结果
            logger.info(f"实际{from_symbol}花费: {actual_from_token_spent_normal:.6f} {from_symbol}")
            logger.info(f"实际{to_symbol}获得: {actual_to_token_received_normal:.18f} {to_symbol}")  #临时修改，需改回为.6f
            logger.info(f"实际BNB花费: {actual_bnb_spent_normal:.8f} BNB")
            logger.info(f"实际滑点: {actual_slippage:.2f}%")
            logger.info(f"预期滑点容忍度: {SLIPPAGE_TOLERANCE * 100}%")
            
            # 检查交易是否成功（余额有变化）
            if actual_to_token_received > 0:
                logger.info("交易成功完成!")
            else:
                logger.warning("交易可能未成功执行，代币余额无变化")
            
            return bundle_hash
        else:
            logger.error("Bundle交易提交失败")
            return None
        
    except Exception as e:
        logger.error(f"执行bundle swap失败: {str(e)}")
        return None

# === 执行入口 ===
if __name__ == "__main__":
    if not PRIVATE_KEY:
        logger.error("未设置PRIVATE_KEY环境变量")
        exit(1)
    
    # 根据交易方向选择代币对
    if TRADE_DIRECTION == 1:
        from_t, to_t = TOKENS["WBNB"], TOKENS["USDT"]
        amt = Decimal("0.0001")  # 正向交易：0.001 WBNB → USDT
    else:
        from_t, to_t = TOKENS["USDT"], TOKENS["WBNB"]
        amt = Decimal("0.05")  # 反向交易：0.5 USDT → WBNB
    
    logger.info("=" * 60)
    logger.info("BSC主网 Bundle Swap Bot (48Club Puissant Builder)")
    logger.info("=" * 60)
    
    # 执行bundle交易
    bundle_hash = execute_swap_with_bundle(amt, from_t, to_t, PRIVATE_KEY)
    
    if bundle_hash:
        logger.info(f"Bundle Hash: {bundle_hash}")
    else:
        logger.error("Bundle交易提交失败")