import os
import time
import yaml   #安的不是这个库，是pip install pyyaml -i https://pypi.tuna.tsinghua.edu.cn/simple
import json
import base64 
import logging
import requests
from decimal import Decimal, getcontext
from web3.exceptions import ContractLogicError
from web3 import Web3
from dotenv import load_dotenv
from web3.middleware import ExtraDataToPOAMiddleware

# ========== ABI 常量 ==========
TOKENBRIDGE_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "token", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
            {"internalType": "uint16", "name": "recipientChain", "type": "uint16"},
            {"internalType": "bytes32", "name": "recipient", "type": "bytes32"},
            {"internalType": "uint256", "name": "arbiterFee", "type": "uint256"},
            {"internalType": "uint32", "name": "nonce", "type": "uint32"}
        ],
        "name": "transferTokens",
        "outputs": [{"internalType": "uint64", "name": "sequence", "type": "uint64"}],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "token", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
            {"internalType": "uint16", "name": "recipientChain", "type": "uint16"},
            {"internalType": "bytes32", "name": "recipient", "type": "bytes32"},
            {"internalType": "uint32", "name": "nonce", "type": "uint32"},
            {"internalType": "bytes", "name": "payload", "type": "bytes"}
        ],
        "name": "transferTokensWithPayload",
        "outputs": [{"internalType": "uint64", "name": "sequence", "type": "uint64"}],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes", "name": "encodedVm", "type": "bytes"}],
        "name": "completeTransfer",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes", "name": "encodedVm", "type": "bytes"}],
        "name": "completeTransferWithPayload",
        "outputs": [{"internalType": "bytes", "name": "", "type": "bytes"}],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

ERC20_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "_spender", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
    "constant": True,
    "inputs": [
        {"name": "owner", "type": "address"},
        {"name": "spender", "type": "address"}
    ],
    "name": "allowance",
    "outputs": [{"name": "", "type": "uint256"}],
    "type": "function"
    }
]

# ========== 配置与日志 ==========
def load_config():
    with open("config1.yaml", "r") as f:
        return yaml.safe_load(f)

def setup_logger(log_level="INFO"):
    logger = logging.getLogger("wormhole")
    logger.setLevel(getattr(logging, log_level.upper()))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh = logging.FileHandler("wormhole.log")
    fh.setFormatter(formatter)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

# ========== 工具 ==========
def to_bytes32(address: str) -> bytes:
    # 地址转bytes32
    addr = Web3.to_bytes(hexstr=address)
    return addr.rjust(32, b'\0')

def amount_to_min_unit(amount_str, decimals):
    # 十进制金额转最小单位
    getcontext().prec = 80
    return int(Decimal(amount_str) * Decimal(10 ** decimals))

def checksum(address):
    # 地址转checksum格式
    return Web3.to_checksum_address(address)

def sleep_with_log(seconds, logger):
    logger.debug(f"休眠 {seconds} 秒...")
    time.sleep(seconds)

# ========== Web3 初始化 ==========
def init_web3(rpc_url, enable_poa_middleware=False):  # 新增参数：是否启用POA中间件
    """
    初始化web3对象，连接指定RPC，连接失败抛出异常
    """
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
    
    # ========== 新增：根据开关动态注入POA中间件 ==========
    if enable_poa_middleware:
        # 仅POA链注入中间件，禁用extraData长度校验
        # layer=0表示最内层中间件，优先处理区块数据解析
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        logging.getLogger("wormhole").debug(f"已为RPC {rpc_url} 注入POA中间件")
    
    if not w3.is_connected():
        raise RuntimeError(f"Web3 连接失败: {rpc_url}")
    return w3

# ========== 新增：EIP-1559 Gas参数构建工具 ==========
def build_tx_with_gas_params(w3, tx_dict, logger):
    """
    构建交易参数：
    - 非 EIP-1559 链：使用 gasPrice
    - EIP-1559 链：强制使用 maxFeePerGas / maxPriorityFeePerGas
      priority fee 为 0 时使用兜底值，而不是回退
    """

    tx = tx_dict.copy()
    tx["chainId"] = w3.eth.chain_id

    FALLBACK_PRIORITY_FEE = 1000000      # 0.001 gwei
    BASE_FEE_MULTIPLIER = 1.2

    try:
        # ---------- 1. 探测 baseFee ----------
        latest_block = w3.eth.get_block("latest")
        base_fee = latest_block.get("baseFeePerGas", 0)

        # ---------- 2. 非 EIP-1559 链 ----------
        if base_fee is None or base_fee == 0:
            logger.info("检测到非 EIP-1559 链，使用 gasPrice")

            gas_price = w3.eth.gas_price
            tx["gasPrice"] = gas_price

            # 清理 EIP-1559 字段
            tx.pop("maxFeePerGas", None)
            tx.pop("maxPriorityFeePerGas", None)

            logger.info(f"gasPrice = {Web3.from_wei(gas_price, 'gwei')} gwei")
            return tx

        # ---------- 3. EIP-1559 链 ----------
        try:
            priority_fee = int(w3.eth.max_priority_fee)
        except Exception:
            priority_fee = 0

        if priority_fee <= 0:
            logger.warning(
                f"RPC 返回 maxPriorityFeePerGas={priority_fee}，使用兜底值 {FALLBACK_PRIORITY_FEE}"
            )
            priority_fee = FALLBACK_PRIORITY_FEE

        max_fee = int(base_fee * BASE_FEE_MULTIPLIER) + priority_fee

        tx["maxFeePerGas"] = max_fee
        tx["maxPriorityFeePerGas"] = priority_fee

        # 清理 legacy 字段
        tx.pop("gasPrice", None)

        logger.info(
            "使用 EIP-1559 参数构建交易: "
            f"baseFee={Web3.from_wei(base_fee, 'gwei')} gwei, "
            f"maxFeePerGas={Web3.from_wei(max_fee, 'gwei')} gwei, "
            f"maxPriorityFeePerGas={Web3.from_wei(priority_fee, 'gwei')} gwei"
        )

        return tx

    except Exception as e:
        logger.error(f"构建 gas 参数失败: {e}")
        raise

# ========== 主流程 ==========
def main():
    # 1. 加载配置和私钥
    config = load_config()
    load_dotenv()
    logger = setup_logger(config.get("log_level", "INFO"))
    logger.info("配置和日志系统加载完成。")

    mode = config["mode"]
    wtt_method = config["wtt_method"]
    src = config["src"]
    dst = config["dst"]
    token = config["token"]
    recipient_on_dst = config["recipient_on_dst"]
    amount = config["amount"]
    private_key = os.getenv(config["private_key_env"])
    wormholescan_api_base = config["wormholescan_api_base"]
    vaa_poll_interval = float(config.get("vaa_poll_interval_seconds", 0.1))
    vaa_alert_interval = int(config.get("vaa_alert_interval_seconds", 60))
    vaa_alert_timeout = int(config.get("vaa_alert_timeout_seconds", 600))
    token_bridge_contract_src = config["token_bridge_contract_src"]
    token_bridge_contract_dst = config["token_bridge_contract_dst"]
    payload_hex = config.get("payload", "")
    src_tx_hash = config.get("src_tx_hash", "")
    wormhole_dst_chain_id = dst["wormhole_evm_id"]

    # 2. 初始化web3（传入is_poa参数），默认False（兼容未配置的情况）
    w3_src = init_web3(src["rpc"], enable_poa_middleware=src.get("is_poa", False))
    w3_dst = init_web3(dst["rpc"], enable_poa_middleware=dst.get("is_poa", False))
    account = w3_src.eth.account.from_key(private_key)
    logger.info(f"使用账户: {account.address}")
    erc20 = w3_src.eth.contract(address=checksum(token["address_on_src"]), abi=ERC20_ABI)
    min_unit_amount = amount_to_min_unit(amount, token["decimals"])

    # 3. 检查余额
    if mode == "full_send":
        balance = erc20.functions.balanceOf(account.address).call()
        
        # 日志：当前余额和跨链代币数量
        human_balance = Decimal(balance) / Decimal(10 ** token["decimals"])
        human_amount = Decimal(amount)
        logger.info(f"当前余额: {human_balance} {token['symbol']}")
        logger.info(f"跨链代币数量: {human_amount} {token['symbol']}")
        
        if balance < min_unit_amount:
            logger.error(f"代币余额不足: {balance} < {min_unit_amount}")
            return

        # 4. 授权 approve
        if token.get("approve_required", True) and mode == "full_send":
            allowance = erc20.functions.allowance(account.address, checksum(token_bridge_contract_src)).call()
            if allowance < min_unit_amount:
                logger.info("开始授权代币...")
                nonce = w3_src.eth.get_transaction_count(account.address)
                approve_tx_dict = {
                    "from": account.address,
                    "nonce": nonce,
                    "gas": 100000,
                    "value": 0
                }
                # 构建交易参数（优先EIP-1559，回退gasPrice）
                approve_tx_dict = build_tx_with_gas_params(w3_src, approve_tx_dict, logger)
                tx = erc20.functions.approve(token_bridge_contract_src, min_unit_amount).build_transaction(approve_tx_dict)
                signed = w3_src.eth.account.sign_transaction(tx, private_key)
                tx_hash = w3_src.eth.send_raw_transaction(signed.raw_transaction)
                logger.info(f"授权交易已发送: {tx_hash.hex()}")
                w3_src.eth.wait_for_transaction_receipt(tx_hash)
                logger.info("授权交易已上链")

        # 5. full_send模式发起跨链
            logger.info("发起跨链转账...")
            tb = w3_src.eth.contract(address=checksum(token_bridge_contract_src), abi=TOKENBRIDGE_ABI)
            recipient_bytes32 = to_bytes32(recipient_on_dst)
            
            # 增加详细日志
            logger.info(f"跨链目标地址: {recipient_on_dst}")
            logger.info(f"目标链名称: {dst['name']}")
            logger.info(f"虫洞目标链ID: {wormhole_dst_chain_id}")
            logger.info(f"跨链代币数量: {amount} {token['symbol']}")
            
            nonce = w3_src.eth.get_transaction_count(account.address)
            if wtt_method == "transferTokens":
                func = tb.functions.transferTokens(
                    checksum(token["address_on_src"]),
                    min_unit_amount,
                    wormhole_dst_chain_id,
                    recipient_bytes32,
                    0,  # arbiterFee
                    nonce
                )
            else:
                # 支持payload从配置文件输入
                if payload_hex.startswith("0x"):
                    payload_bytes = bytes.fromhex(payload_hex[2:])
                else:
                    payload_bytes = b''
                func = tb.functions.transferTokensWithPayload(
                    checksum(token["address_on_src"]),
                    min_unit_amount,
                    wormhole_dst_chain_id,
                    recipient_bytes32,
                    nonce,
                    payload_bytes
                )
            tx_dict = {
                "from": account.address,
                "nonce": nonce,
                "gas": 500000,
                "value": 0
            }
            # 构建交易参数（优先EIP-1559，回退gasPrice）
            tx_dict = build_tx_with_gas_params(w3_src, tx_dict, logger)
            tx = func.build_transaction(tx_dict)
            signed = w3_src.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3_src.eth.send_raw_transaction(signed.raw_transaction)
            logger.info(f"跨链交易已发送: {tx_hash.hex()}")
            receipt = w3_src.eth.wait_for_transaction_receipt(tx_hash)
            logger.info(f"跨链交易已上链: {receipt.transactionHash.hex()}")
            src_tx_hash = tx_hash.hex()
    else:
        # redeem_only模式下，src_tx_hash必须从配置文件读取
        if not src_tx_hash:
            logger.error("redeem_only模式下，必须在配置文件中提供src_tx_hash")
            return

    # 6. 轮询 WormholeScan 获取 VAA 并校验
    logger.info("开始轮询 WormholeScan 获取 VAA...")
    vaa = None
    parsed_payload = None
    start_time = time.time()
    last_alert_time = 0
    while True:
        try:
            resp = requests.get(
                f"{wormholescan_api_base}/vaas/?page=0&pageSize=5&sortOrder=ASC&txHash={src_tx_hash}&parsedPayload=true",
                headers={"accept": "application/json"}
            )
            # 校验响应状态码为200（正常响应）
            if resp.status_code == 200:
                data = resp.json()
                # 提取data列表，若不存在则默认为空列表，增强健壮性
                vaa_data_list = data.get("data", [])
                if not vaa_data_list:
                    # 数据列表为空，说明VAA尚未生成
                    logger.info("vaa还未签名，继续轮询获取中...")
                else:
                    # 数据列表非空，筛选带payload的VAA（保留原逻辑）
                    for vaa_data in vaa_data_list:
                        if "payload" in vaa_data and vaa_data["payload"] is not None:
                            vaa = vaa_data["vaa"]
                            parsed_payload = vaa_data["payload"]
                            logger.info(f"找到带payload的VAA: sequence={vaa_data.get('sequence')}, emitterChain={vaa_data.get('emitterChain')}")
                            logger.info(f"VAA 已获取: {vaa[:32]}... (base64)")
                            break
                
                if vaa and parsed_payload:
                    # 在获取到VAA后立即进行校验
                    logger.info("开始解析并校验 VAA...")
                    try:
                        # 校验amount, toAddress, tokenAddress, toChain
                        normalized_amount = int(parsed_payload.get("amount"))
                        scale = 10 ** (token["decimals"] - token["wormhole_declaims"])
                        reconstructed_amount = normalized_amount * scale
                        if str(reconstructed_amount) != str(min_unit_amount):
                            logger.error(f"VAA 金额校验失败: 解析值 {reconstructed_amount} vs 预期值 {min_unit_amount}")
                            return
                        else:
                            # 计算十进制金额（最小单位转正常显示）
                            token_decimals = token["decimals"]
                            decimal_amount = Decimal(min_unit_amount) / (10 ** token_decimals)
                            decimal_amount = decimal_amount.normalize()
                            logger.info(f"VAA金额校验成功: {decimal_amount} {token['symbol']}")
                        
                        # 校验接收地址
                        if parsed_payload.get("toAddress", "").lower()[-40:] != recipient_on_dst.lower()[-40:]:
                            logger.error(f"VAA 接收地址校验失败：解析值 {parsed_payload.get('toAddress', '')} vs 预期值 {recipient_on_dst}")
                            return
                        else:
                            logger.info(f"VAA地址校验成功: {parsed_payload.get('toAddress', '')}")
                        
                        # 校验目标链ID
                        if int(parsed_payload.get("toChain")) != wormhole_dst_chain_id:
                            logger.error(f"VAA 目标链ID校验失败：解析值 {parsed_payload.get('toChain')} vs 预期值 {wormhole_dst_chain_id}")
                            return
                        else:
                            logger.info(f"VAA目标链ID校验成功: {parsed_payload.get('toChain')}")
                        
                        logger.info("VAA 所有校验通过")
                        break
                    except Exception as e:
                        logger.error(f"VAA 校验失败: {e}")
                        return
                else:
                    # 没有找到带payload的VAA，继续轮询
                    elapsed = int(time.time() - start_time)
                    if elapsed - last_alert_time >= vaa_alert_interval and elapsed >= vaa_alert_timeout:
                        minutes = elapsed // 60  # 整除60得到分钟数
                        seconds = elapsed % 60   # 取余60得到剩余秒数
                    if elapsed - last_alert_time >= vaa_alert_interval and elapsed >= vaa_alert_timeout:
                        logger.warning(f"等待带payload的VAA已超过 {minutes} 分 {seconds} 秒...")
                        last_alert_time = elapsed
                    sleep_with_log(vaa_poll_interval, logger)
            else:
                # 响应状态码非200，属于异常情况
                logger.error(f"WormholeScan API响应状态码异常: {resp.status_code}，响应内容: {resp.text}")
            # 若找到VAA则退出循环
            if vaa and parsed_payload:
                break
        except Exception as e:
            # 捕获网络异常、JSON解析失败等情况，区分于数据为空的正常情况
            logger.error(f"轮询VAA时发生异常（网络/解析等问题）: {str(e)}")

    # 8. 幂等性检查
    logger.info("检查 VAA 是否已在目标链执行...")
    try:
        response = requests.get(
            f"{wormholescan_api_base}/live-tracking/subscribe?txHash={src_tx_hash}",
            headers={"accept": "application/json"},
            stream=True,
            timeout=10
        )
    except Exception as e:
        logger.warning(f"Live tracking 请求异常：{e}. 将直接尝试赎回。")
        response = None

    found_completed = False
    if response is not None:
        try:
            if response.status_code != 200:
                logger.warning(f"Live tracking 请求失败，状态码: {response.status_code}")
            else:
                lines_iter = response.iter_lines(decode_unicode=True)
                start_time = time.time()
                timeout_seconds = 5
                current_event = None
                for line in lines_iter:
                    # 超时控制
                    if time.time() - start_time > timeout_seconds:
                        logger.info("Live tracking 读取超时，将尝试继续执行赎回")
                        break
                    if not line:
                        continue
                    # SSE 解析
                    try:
                        s = line.strip()
                        if s.startswith("event:"):
                            current_event = s[len("event:"):].strip()
                        elif s.startswith("data:"):
                            data_str = s[len("data:"):].strip()
                            data = json.loads(data_str)
                            # 打印详细的event和status日志
                            event = data.get('event', '')
                            status = data.get('status', '')
                            if current_event == 'SOURCE_TX':
                                logger.info(f'"event":"SOURCE_TX","status":"{status}"')
                            elif current_event == 'SIGNED_VAA':
                                logger.info(f'"event":"SIGNED_VAA","status":"{status}"')
                            elif current_event == 'VAA_REDEEMED':
                                logger.info(f'"event":"VAA_REDEEMED","status":"{status}"')
                                if status == 'DONE':
                                    event_data = data.get('data', {})
                                    if event_data.get('chainId') == wormhole_dst_chain_id:
                                        logger.info(f"VAA 已在目标链执行，目标链交易哈希: {event_data.get('txHash')}")
                                        found_completed = True
                                        break
                                elif status == 'PENDING' and data.get('data', {}).get('chainId') == wormhole_dst_chain_id:
                                    logger.info("检测到VAA在目标链为PENDING，需要执行赎回")
                                    break
                            elif current_event == 'END_OF_WORKFLOW':
                                logger.info(f'"event":"END_OF_WORKFLOW","status":"{status}","data":{json.dumps(data.get("data", {}))}')
                                if status == 'DONE':
                                    logger.info("所有工作流已完成")
                    except json.JSONDecodeError:
                        logger.debug("无法解析 SSE data 为 JSON")
                    except Exception as ee:
                        logger.debug(f"SSE 处理过程中发生异常: {ee}")
        finally:
            try:
                response.close()
            except Exception:
                pass

    if found_completed:
        logger.info("跨链已完成，退出程序")
        return
    else:
        logger.info("VAA尚未在目标链执行，将进行 claim 操作")

    # 9. 目标链claim
    logger.info("在目标链执行 claim 操作...")
    # 初始化目标链的Token Bridge合约实例
    tb_dst = w3_dst.eth.contract(
        address=checksum(token_bridge_contract_dst),
        abi=TOKENBRIDGE_ABI
    )
    # 将Base64编码的VAA解码为字节数据
    encodedVm_bytes = base64.b64decode(vaa)
    logger.info("VAA已完成Base64解码，准备构建交易")

    # 根据传输类型选择对应的合约函数
    if wtt_method == "transferTokensWithPayload":
        func = tb_dst.functions.completeTransferWithPayload(encodedVm_bytes)
    else:
        func = tb_dst.functions.completeTransfer(encodedVm_bytes)

    nonce = w3_dst.eth.get_transaction_count(account.address, 'pending')
    tx_for_estimate = {
        "from": account.address,  # 交易发起地址
        "nonce": nonce,           # 交易nonce
        "value": 0                # 转账金额（VAA claim通常为0）
    }
    # 估算Gas消耗量
    try:
        estimated_gas = func.estimate_gas(tx_for_estimate)
        gas_limit = int(estimated_gas * 1.3)  # 增加30%作为Gas上限，应对链上波动
        logger.info(f"Gas估算完成 - 估算值: {estimated_gas}, 最终上限: {gas_limit}")
    except Exception as e:
        logger.warning(f"Gas估算失败: {e}，使用默认Gas上限500000")
        gas_limit = 500000

    # 构建交易参数（优先EIP-1559，回退gasPrice）
    tx_dict = {
        "from": account.address,
        "nonce": nonce,
        "gas": gas_limit,
        "value": 0
    }
    tx_dict = build_tx_with_gas_params(w3_dst, tx_dict, logger)
    tx = func.build_transaction(tx_dict)
    logger.info("交易参数构建完成，准备签名")

    # 使用私钥对交易进行签名
    signed_tx = w3_dst.eth.account.sign_transaction(tx, private_key)
    logger.info("交易签名完成，准备发送到目标链")

    # 发送签名后的原始交易到目标链
    tx_hash = w3_dst.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_hash_hex = tx_hash.hex()
    logger.info(f"目标链claim交易已发送，交易哈希: {tx_hash_hex}")

    # 等待交易上链确认（超时120秒，轮询间隔1秒）
    receipt = w3_dst.eth.wait_for_transaction_receipt(tx_hash, timeout=120, poll_latency=1)
    if receipt.status == 1:
        # 交易状态为1表示执行成功
        logger.info(f"目标链claim交易执行成功 - 区块高度: {receipt.blockNumber}, Gas消耗: {receipt.gasUsed}")
    else:
        # 交易状态为0表示执行失败（合约回滚等原因）
        logger.error(f"目标链claim交易执行失败，交易哈希: {tx_hash_hex}")

if __name__ == "__main__":
    main()