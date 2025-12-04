import os
import time
import yaml
import logging
import requests
from decimal import Decimal, getcontext
from web3 import Web3
from dotenv import load_dotenv

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
    }
]

# ========== Wormhole chain id 映射 ==========
WORMHOLE_CHAIN_ID_MAP = {
    "ethereum": 2,
    "bsc": 4,
    "polygon": 5,
    "avalanche": 6,
    "arbitrum": 23,
    "optimism": 24,
    "base": 30,
    # ...可补充更多
}

# ========== 配置与日志 ==========
def load_config():
    with open("config.yaml", "r") as f:
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
    addr = Web3.toBytes(hexstr=address)
    return addr.rjust(32, b'\0')

def amount_to_min_unit(amount_str, decimals):
    # 十进制金额转最小单位
    getcontext().prec = 80
    return int(Decimal(amount_str) * Decimal(10 ** decimals))

def checksum(address):
    # 地址转checksum格式
    return Web3.toChecksumAddress(address)

def sleep_with_log(seconds, logger):
    logger.debug(f"休眠 {seconds} 秒...")
    time.sleep(seconds)

# ========== Web3 初始化 ==========
def init_web3(rpc_url):
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        print("RPC连接失败，请检查RPC地址")
        return None
    return w3

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

    # 2. 初始化web3
    w3_src = init_web3(src["rpc"])
    w3_dst = init_web3(dst["rpc"])
    account = w3_src.eth.account.from_key(private_key)
    logger.info(f"使用账户: {account.address}")

    # 3. 检查余额
    erc20 = w3_src.eth.contract(address=checksum(token["address_on_src"]), abi=ERC20_ABI)
    min_unit_amount = amount_to_min_unit(amount, token["decimals"])
    balance = erc20.functions.balanceOf(account.address).call()
    if balance < min_unit_amount:
        logger.error(f"代币余额不足: {balance} < {min_unit_amount}")
        return

    # 4. 授权 approve
    if token.get("approve_required", True) and mode == "full_send":
        logger.info("开始授权代币...")
        nonce = w3_src.eth.get_transaction_count(account.address)
        tx = erc20.functions.approve(token_bridge_contract_src, min_unit_amount).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 100000,
            "gasPrice": w3_src.eth.gas_price,
        })
        signed = w3_src.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3_src.eth.send_raw_transaction(signed.rawTransaction)
        logger.info(f"授权交易已发送: {tx_hash.hex()}")
        w3_src.eth.wait_for_transaction_receipt(tx_hash)
        logger.info("授权交易已上链")

    # 5. full_send模式发起跨链
    if mode == "full_send":
        logger.info("发起跨链转账...")
        tb = w3_src.eth.contract(address=checksum(token_bridge_contract_src), abi=TOKENBRIDGE_ABI)
        recipient_bytes32 = to_bytes32(recipient_on_dst)
        wormhole_dst_chain_id = WORMHOLE_CHAIN_ID_MAP[dst["name"]]
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
        tx = func.build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 500000,
            "gasPrice": w3_src.eth.gas_price,
            "value": 0
        })
        signed = w3_src.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3_src.eth.send_raw_transaction(signed.rawTransaction)
        logger.info(f"跨链交易已发送: {tx_hash.hex()}")
        receipt = w3_src.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"跨链交易已上链: {receipt.transactionHash.hex()}")
        src_tx_hash = tx_hash.hex()
    else:
        # redeem_only模式下，src_tx_hash必须从配置文件读取
        if not src_tx_hash:
            logger.error("redeem_only模式下，必须在配置文件中提供src_tx_hash")
            return

    # 6. 轮询 WormholeScan 获取 VAA
    logger.info("开始轮询 WormholeScan 获取 VAA...")
    vaa = None
    start_time = time.time()
    last_alert_time = 0
    while True:
        try:
            resp = requests.get(
                f"{wormholescan_api_base}/vaas/?txHash={src_tx_hash}",
                headers={"accept": "application/json"}
            )
            data = resp.json()
            if data.get("data"):
                vaa = data["data"][0]["vaa"]
                logger.info(f"VAA 已获取: {vaa[:32]}... (base64)")
                break
            else:
                elapsed = int(time.time() - start_time)
                if elapsed - last_alert_time >= vaa_alert_interval and elapsed >= vaa_alert_timeout:
                    logger.warning(f"等待 VAA 已超过 {elapsed} 秒...")
                    last_alert_time = elapsed
                sleep_with_log(vaa_poll_interval, logger)
        except Exception as e:
            logger.error(f"轮询 VAA 发生异常: {e}")
            sleep_with_log(vaa_poll_interval, logger)

    # 7. 解析VAA并校验
    logger.info("解析并校验 VAA...")
    try:
        resp = requests.post(
            f"{wormholescan_api_base}/vaas/parse",
            json={"vaa": vaa},
            headers={"accept": "application/json"}
        )
        parsed = resp.json()
        payload = parsed.get("parsedPayload", {})
        # 校验amount, toAddress, tokenAddress, toChain
        if str(payload.get("amount")) != str(min_unit_amount):
            logger.error("VAA 金额校验失败")
            return
        if payload.get("toAddress", "").lower()[-40:] != recipient_on_dst.lower()[-40:]:
            logger.error("VAA 接收地址校验失败")
            return
        if payload.get("tokenAddress", "").lower()[-40:] != token["address_on_src"].lower()[-40:]:
            logger.error("VAA 代币地址校验失败")
            return
        if int(payload.get("toChain")) != WORMHOLE_CHAIN_ID_MAP[dst["name"]]:
            logger.error("VAA 目标链ID校验失败")
            return
        logger.info("VAA 校验通过")
    except Exception as e:
        logger.error(f"VAA 解析或校验失败: {e}")
        return

    # 8. 冪等性检查
    logger.info("检查 VAA 是否已在目标链执行...")
    try:
        resp = requests.get(
            f"{wormholescan_api_base}/live-tracking/subscribe?txHash={src_tx_hash}",
            headers={"accept": "application/json"}
        )
        events = resp.json()
        for event in events:
            if event.get("event") == "VAA_REDEEMED" and event.get("status") == "DONE":
                logger.info(f"VAA 已在目标链执行，目标链交易哈希: {event['data'].get('txHash')}")
                return
    except Exception as e:
        logger.warning(f"Live tracking 检查失败: {e}")

    # 9. 目标链claim
    logger.info("在目标链执行 claim 操作...")
    tb_dst = w3_dst.eth.contract(address=checksum(token_bridge_contract_dst), abi=TOKENBRIDGE_ABI)
    encoded_vm = Web3.toBytes(base64str=vaa)
    nonce = w3_dst.eth.get_transaction_count(account.address)
    if wtt_method == "transferTokensWithPayload":
        func = tb_dst.functions.completeTransferWithPayload(encoded_vm)
    else:
        func = tb_dst.functions.completeTransfer(encoded_vm)
    try:
        tx = func.build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 800000,
            "gasPrice": w3_dst.eth.gas_price,
        })
        signed = w3_dst.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3_dst.eth.send_raw_transaction(signed.rawTransaction)
        logger.info(f"目标链 claim 交易已发送: {tx_hash.hex()}")
        receipt = w3_dst.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"目标链 claim 交易已上链: {receipt.transactionHash.hex()}")
    except Exception as e:
        logger.error(f"目标链 claim 操作失败: {e}")

if __name__ == "__main__":
    main()