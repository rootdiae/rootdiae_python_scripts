import os
import time
import yaml
import json
import base64 
import logging
import requests
from decimal import Decimal, getcontext
from web3.exceptions import ContractLogicError
from web3 import Web3
from dotenv import load_dotenv

# 无法在目标链执行交易，gas估计失败，claim revert（Status:Fail with error 'invalid target chain'）


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
    "arbitrum": 10003,
    "optimism": 24,
    "base": 30,
    # ...可补充更多
}

# ========== 配置与日志 ==========
def load_config():
    with open("WormholeWTTBridge/config.yaml", "r") as f:
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
        tx_hash = w3_src.eth.send_raw_transaction(signed.raw_transaction)
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

    # 6. 轮询 WormholeScan 获取 VAA
    logger.info("开始轮询 WormholeScan 获取 VAA...")
    vaa = None
    start_time = time.time()
    last_alert_time = 0
    while True:
        try:
            resp = requests.get(
                f"{wormholescan_api_base}/vaas/?page=0&pageSize=5&sortOrder=ASC&txHash={src_tx_hash}",
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
    
        # WTT 统一使用 8 decimals 表示金额，需要转换
        normalized_amount = int(payload.get("amount"))
        scale = 10 ** (token["decimals"] - 8)
        reconstructed_amount = normalized_amount * scale
        if str(reconstructed_amount) != str(min_unit_amount):
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
    # ---------- 在此处插入：验证 VAA 的 toChain 与目标链配置一致 ----------
    # parsed 变量由之前的 /vaas/parse 返回得到
    # -------------------- 增加诊断性检查（不会发送 tx，仅读取链上状态） --------------------
    # 参数：w3_dst, tb_dst (可延后构造), parsed, vaa (base64 str)
    try:
        import hashlib
        from eth_utils import keccak, to_hex

        # 1) 打印 parsed.vaa 的关键信息
        vaa_info = parsed.get("vaa", {})
        logger.info(f"parsed.vaa summary: emitterChain={vaa_info.get('emitterChain')}, "
                    f"emitterAddress={vaa_info.get('emitterAddress')}, "
                    f"sequence={vaa_info.get('sequence')}, "
                    f"nonce={vaa_info.get('nonce')}, "
                    f"guardianSetIndex={vaa_info.get('guardianSetIndex')}")

        # 2) 打印 parsedPayload 详细信息
        payload = parsed.get("parsedPayload", {})
        logger.info(f"parsedPayload: amount={payload.get('amount')}, tokenChain={payload.get('tokenChain')}, "
                    f"tokenAddress={payload.get('tokenAddress')}, toChain={payload.get('toChain')}, "
                    f"toAddress={payload.get('toAddress')}, payloadType={payload.get('payloadType')}")

        # 3) decode vaa -> raw bytes, 打印前后若干 hex 便于比对
        vaa_raw = base64.b64decode(vaa)
        logger.info(f"VAA raw bytes length: {len(vaa_raw)}; head(64 bytes) hex: {vaa_raw[:64].hex()}")

        # 4) 计算 keccak256(vaa_raw) —— 这是合约用来标记 redeemed 的 hash（Bridge 源码中用于 completedTransfers）
        vaa_keccak = keccak(vaa_raw)  # 返回 bytes
        logger.info(f"keccak256(VAA) (bytes32 hex): {vaa_keccak.hex()}")

        # 5) 构造目标链 bridge 合约对象（如果尚未）
        try:
            tb_dst = w3_dst.eth.contract(address=checksum(token_bridge_contract_dst), abi=TOKENBRIDGE_ABI)
        except Exception as e:
            logger.warning(f"构造目标链 TokenBridge 合约对象失败: {e}")
            tb_dst = None

        # 6) 尝试查询 completedTransfers 或 isTransferCompleted（两种 getter 都尝试）
        if tb_dst:
            checked = False
            try:
                # 尝试 public mapping getter completedTransfers(bytes32)
                try:
                    res = tb_dst.functions.completedTransfers(vaa_keccak).call()
                    logger.info(f"读取 completedTransfers(keccak) => {res}")
                    checked = True
                except Exception as e:
                    logger.debug(f"completedTransfers getter 不可用或调用失败: {e}")

                # 尝试 isTransferCompleted(bytes32)
                try:
                    res2 = tb_dst.functions.isTransferCompleted(vaa_keccak).call()
                    logger.info(f"读取 isTransferCompleted(keccak) => {res2}")
                    checked = True
                except Exception as e:
                    logger.debug(f"isTransferCompleted getter 不可用或调用失败: {e}")

                # 若都失败，尝试 completedTransfer(keccak) 或者其他命名（宽容处理）
                if not checked:
                    logger.warning("目标链 Bridge 合约未暴露常见 redeemed getter（completedTransfers/isTransferCompleted）或调用失败。")
            except Exception as e:
                logger.warning(f"查询 redeemed 状态时发生异常: {e}")
        else:
            logger.warning("tb_dst 对象为空，略过链上 redeemed 检查。")

        # 7) 尝试读取合约可能暴露的 chain id 变量（若实现）
        if tb_dst:
            for candidate in ["chainId", "thisChainId", "getChainId", "chainid", "WORMHOLE_CHAIN_ID"]:
                try:
                    fn = getattr(tb_dst.functions, candidate, None)
                    if fn:
                        try:
                            v = fn().call()
                            logger.info(f"Bridge 合约返回 {candidate} = {v}")
                        except Exception:
                            # 某些函数可能需要参数或不存在，这里忽略调用错误
                            pass
                except Exception:
                    pass

        # 8) 最后打印一些对照信息，方便人工核查
        logger.info("诊断信息打印完成：请比对 parsedPayload.toChain 与 Bridge 合约的内部链 ID（若Bridge提供）。如仍报 invalid target chain，说明 Bridge 合约与 VAA 的目标 chain id 不匹配（可能 Bridge 地址配置错误或此 VAA 发往别的网络）。")
    except Exception as diag_e:
        logger.error(f"诊断检查出错: {diag_e}")
    # -------------------- 诊断结束 --------------------


    try:
        vaa_parsed_payload = parsed.get("parsedPayload", {})
        vaa_to_chain = int(vaa_parsed_payload.get("toChain", -1))
        wormhole_dst_chain_id = WORMHOLE_CHAIN_ID_MAP.get(dst["name"])
        logger.info(f"VAA parsed toChain={vaa_to_chain}, expected dst wormhole chain id={wormhole_dst_chain_id}")
        if wormhole_dst_chain_id is None:
            logger.error(f"目标链名称 '{dst['name']}' 在 WORMHOLE_CHAIN_ID_MAP 中没有配置，请检查 config.yaml")
            return

        # 如果VAA中toChain与目标链不符，直接退出（避免上链失败）
        if vaa_to_chain != wormhole_dst_chain_id:
            logger.error(
                f"VAA 的目标链（toChain={vaa_to_chain}）与配置的目标 Wormhole Chain ID（{wormhole_dst_chain_id}）不一致。"
                " 这会导致合约 revert: invalid target chain。请确认你使用的 src_tx_hash 是否为发往该目标链的交易，或修正配置映射。"
            )
            # 额外打印 parsed 的关键字段便于排查
            logger.debug(f"完整 parsedPayload: {json.dumps(vaa_parsed_payload)}")
            logger.debug(f"完整 vaa info: {json.dumps(parsed.get('vaa', {}))}")
            return
        # 如果一致，则继续原先流程（幂等性检查）
    except Exception as e:
        logger.error(f"检查 VAA toChain 时发生异常: {e}")
        return
    # ---------- end toChain 校验 ----------


    # 8. 幂等性检查
    logger.info("检查 VAA 是否已在目标链执行...")
    # ========== Live tracking 检查（更稳健） ==========
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
                            if current_event == 'VAA_REDEEMED':
                                status = data.get('status')
                                event_data = data.get('data', {})
                                if status == 'DONE' and event_data.get('chainId') == wormhole_dst_chain_id:
                                    logger.info(f"VAA 已在目标链执行，目标链交易哈希: {event_data.get('txHash')}")
                                    found_completed = True
                                    break
                                elif status == 'PENDING' and event_data.get('chainId') == wormhole_dst_chain_id:
                                    logger.info("检测到VAA在目标链为PENDING，需要执行赎回")
                                    break
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
        logger.info("VAA尚未在目标链执行，将进行赎回操作")

    # 9. 目标链claim（改进版）
    logger.info("在目标链执行 claim 操作...")
    tb_dst = w3_dst.eth.contract(address=checksum(token_bridge_contract_dst), abi=TOKENBRIDGE_ABI)
    encodedVm_bytes = base64.b64decode(vaa)   # bytes 类型（必须）
    nonce = w3_dst.eth.get_transaction_count(account.address)

    try:
        if wtt_method == "transferTokensWithPayload":
            func = tb_dst.functions.completeTransferWithPayload(encodedVm_bytes)
        else:
            func = tb_dst.functions.completeTransfer(encodedVm_bytes)

        # 构建 transaction dict（用于 estimate_gas / call）
        tx_for_estimate = {
            "from": account.address,
            "nonce": nonce,
            # value 一般为 0，除非某些网络需要 messageFee 作为 value
            "value": 0
        }

        # 先尝试 estimate_gas（传入 from/value 等），若合约在模拟时 revert，会抛出异常并带有 revert reason
        try:
            estimated_gas = func.estimate_gas(tx_for_estimate)
            gas_limit = int(estimated_gas * 1.3)
            logger.info(f"Gas 估计成功: estimated={estimated_gas}, gas_limit={gas_limit}")
        except ContractLogicError as cle:
            # Web3 的 ContractLogicError 里通常包含 revert reason bytes，可在 cle.args 里查看
            logger.warning(f"Gas估计时发生合约回滚: {cle}. 可能的 revert reason：{getattr(cle, 'args', cle)}")
            # 如果 revert reason 明确是 invalid target chain，则不必继续发送 tx
            if "invalid target chain" in str(cle).lower():
                logger.error("检测到合约在模拟时返回 invalid target chain，终止赎回。请检查 VAA 的 toChain 与目标链配置是否一致，或确认 token_bridge_contract_dst 是否为目标链的正确 Bridge 合约地址。")
                return
            # 否则使用后备值并尝试继续
            logger.warning("Gas 估计失败，使用默认 gas_limit 并继续尝试发送（非推荐）。")
            gas_limit = 500000

        # 准备 EIP-1559 的 gas 价格参数（与原逻辑类似）
        try:
            fee_data = w3_dst.eth.fee_history(1, 'latest')
            base_fee = int(fee_data['baseFeePerGas'][-1])
            max_priority_fee = int(w3_dst.eth.max_priority_fee)
            max_fee_per_gas = int(base_fee * 1.2)
            if max_priority_fee > max_fee_per_gas * 0.5:
                max_priority_fee = max_fee_per_gas // 10
            logger.info(f"Base Fee: {base_fee}, Max Priority Fee: {max_priority_fee}, Max Fee: {max_fee_per_gas}")
        except Exception as e:
            logger.warning(f"获取fee数据失败: {e}, 使用fallback方法")
            gas_price = w3_dst.eth.gas_price
            max_fee_per_gas = gas_price
            max_priority_fee = int(gas_price * 0.1)

        # 构建并发送交易
        tx = func.build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": gas_limit,
            "maxFeePerGas": max_fee_per_gas,
            "maxPriorityFeePerGas": max_priority_fee,
            "chainId": w3_dst.eth.chain_id,
            "value": 0
        })
        signed = w3_dst.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3_dst.eth.send_raw_transaction(signed.raw_transaction)
        logger.info(f"目标链 claim 交易已发送: {tx_hash.hex()}")

        # 等待交易确认
        receipt = w3_dst.eth.wait_for_transaction_receipt(tx_hash, timeout=120, poll_latency=1)
        if receipt.status == 1:
            logger.info(f"目标链 claim 交易成功: {receipt.transactionHash.hex()}")
            logger.info(f"Gas used: {receipt.gasUsed}")
        else:
            logger.error(f"目标链 claim 交易失败: {receipt.transactionHash.hex()}")
    except Exception as e:
        # 捕获并打印详细异常信息（包含 revert 原因）
        logger.error(f"目标链 claim 操作失败: {e}")
        # 如果异常字符串里包含 revert reason 提示
        if "invalid target chain" in str(e).lower():
            logger.error("Txn revert reason 包含 'invalid target chain'，这表示 VAA 的目标链信息与当前 Bridge 合约不匹配。")
        # 不在这里自动重试，避免重复消耗 gas；若要重试，请根据具体 revert 原因决定


if __name__ == "__main__":
    main()