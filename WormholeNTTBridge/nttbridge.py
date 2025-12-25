import os
import sys
import time
import json
import base64
import logging
from hexbytes import HexBytes
import requests
import yaml  #安的不是这个库，是pip install pyyaml -i https://pypi.tuna.tsinghua.edu.cn/simple
from decimal import Decimal, getcontext
from web3 import Web3
from dotenv import load_dotenv
from web3.middleware import ExtraDataToPOAMiddleware

# ========== 工具函数 ==========

def load_config(path="config.yaml"):
    """
    加载YAML配置文件，返回配置字典
    """
    with open(path, "r") as f:
        return yaml.safe_load(f)

def setup_logger(log_level="INFO", log_file="wormhole.log"):
    """
    配置日志系统，日志同时输出到控制台和文件
    """
    logger = logging.getLogger("wormhole")
    logger.setLevel(getattr(logging, log_level.upper()))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    # 防止重复添加handler
    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(ch)
    return logger

def to_bytes32(address: str) -> bytes:
    """
    将以太坊地址转为bytes32格式，左侧补零
    """
    addr = Web3.to_bytes(hexstr=address)
    return addr.rjust(32, b'\0')

def amount_to_min_unit(amount_str, decimals):
    """
    将十进制字符串金额转换为最小单位整数
    """
    getcontext().prec = 80
    return int(Decimal(amount_str) * Decimal(10 ** decimals))

def checksum(address):
    """
    将地址转换为EIP-55校验格式
    """
    return Web3.to_checksum_address(address)

def sleep_with_log(seconds, logger):
    """
    日志输出休眠信息，并休眠指定秒数
    """
    logger.debug(f"休眠 {seconds} 秒...")
    time.sleep(seconds)

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

# ========== 新增：digest获取函数 ==========
def get_digest_from_src_tx(w3_src, src_tx_hash, logger):
    """
    从源链交易哈希获取digest（TransferSent事件的topic1）
    """
    logger.info(f"正在获取源链交易 {src_tx_hash} 的digest...")
    try:
        receipt = w3_src.eth.get_transaction_receipt(src_tx_hash)
        logs = receipt["logs"]
        
        # 为了兼容的不同的节点，定义多个可能的topic0格式（带或不带0x前缀）
        target_topic0_variants = [
            "0x3e6ae56314c6da8b461d872f41c6d0bb69317b9d0232805aaccfa45df1a16fa0",
            "3e6ae56314c6da8b461d872f41c6d0bb69317b9d0232805aaccfa45df1a16fa0"
        ]
        
        for log in logs:
            if len(log["topics"]) >= 2:
                actual_topic0 = log["topics"][0].hex()  # HexBytes的hex()方法返回不带0x的字符串
                
                # 检查是否匹配任一格式
                for variant in target_topic0_variants:
                    # 统一转换为小写进行比较
                    variant_normalized = variant.lower().replace("0x", "")
                    actual_normalized = actual_topic0.lower()
                    
                    if variant_normalized == actual_normalized:
                        digest = log["topics"][1].hex()
                        logger.info(f"已获取digest: {digest}")
                        return digest
        
        logger.error("未找到TransferSent事件，无法获取digest")
        return None
    except Exception as e:
        logger.error(f"获取digest失败: {e}")
        return None

# ========== VAA轮询和校验函数 ==========
def poll_and_validate_vaa(config, logger, src_tx_hash, min_unit_amount, recipient_on_dst, wormhole_dst_chain_id, token):
    """
    轮询 WormholeScan 获取 VAA，并进行校验，返回vaa和parsed_payload
    """
    wormholescan_api_base = config["runtime"]["wormholescan_api_base"]
    vaa_poll_interval = float(config["runtime"]["vaa_poll_interval_seconds"])
    vaa_alert_interval = int(config["runtime"]["vaa_alert_interval_seconds"])
    vaa_alert_timeout = int(config["runtime"]["vaa_alert_timeout_seconds"])
    vaa = None
    parsed_payload = None
    start_time = time.time()
    last_alert_time = 0
    while True:
        try:
            # 查询WormholeScan API，按txHash查找VAA
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
                    # 数据列表非空，筛选带payload的VAA
                    for vaa_data in vaa_data_list:
                        # 检查payload存在且非空
                        if "payload" in vaa_data and vaa_data["payload"] is not None:
                            vaa = vaa_data["vaa"]
                            parsed_payload = vaa_data["payload"]
                            logger.info(f"找到带payload的VAA:  {vaa[:32]}... (base64)")
                            break  # 找到有效VAA后退出循环
                
                if vaa and parsed_payload:
                    # 在获取到VAA后立即进行校验
                    logger.info("开始解析并校验 VAA...")
                    try:
                        ntt_message = parsed_payload.get("nttMessage", {})
                        trimmed_amount = ntt_message.get("trimmedAmount", {})
                        amount_str = trimmed_amount.get("amount")
                        if amount_str is None:
                            logger.error("VAA 校验失败：未找到 trimmedAmount.amount 字段")
                            return None, None
                        trimmed_decimals = trimmed_amount.get("decimals")
                        if trimmed_decimals != token["wormhole_declaims"]:
                            logger.error(f"VAA 校验失败：trimmedAmount.decimals 不是{token['wormhole_declaims']}，实际为 {trimmed_decimals}")
                            return None, None
                        normalized_amount = int(amount_str)
                        scale = 10 ** (token["decimals"] - token["wormhole_declaims"])
                        reconstructed_amount = normalized_amount * scale
                        if str(reconstructed_amount) != str(min_unit_amount):
                            logger.error(f"VAA 金额校验失败：解析值 {reconstructed_amount} vs 预期值 {min_unit_amount}")
                            return None, None
                        else:
                            token_decimals = token["decimals"]
                            decimal_amount = Decimal(min_unit_amount) / (10 ** token_decimals)
                            decimal_amount = decimal_amount.normalize()
                            logger.info(f"VAA金额校验成功: {decimal_amount} {token['symbol']} (最小单位: {min_unit_amount})")
                        to_address = ntt_message.get("to", "")
                        if not to_address:
                            logger.error("VAA 校验失败：未找到 nttMessage.to 字段")
                            return None, None
                        if to_address.lower()[-40:] != recipient_on_dst.lower()[-40:]:
                            logger.error(f"VAA 接收地址校验失败：解析值 {to_address} vs 预期值 {recipient_on_dst}")
                            return None, None
                        else:
                            logger.info(f"VAA地址校验成功: {to_address}")
                        to_chain = ntt_message.get("toChain")
                        if to_chain is None:
                            logger.error("VAA 校验失败：未找到 nttMessage.toChain 字段")
                            return None, None
                        if int(to_chain) != wormhole_dst_chain_id:
                            logger.error(f"VAA 目标链ID校验失败：解析值 {to_chain} vs 预期值 {wormhole_dst_chain_id}")
                            return None, None
                        else:
                            logger.info(f"VAA目标链ID校验成功: {to_chain}")
                        logger.info("VAA 所有校验通过")
                        break
                    except Exception as e:
                        logger.error(f"VAA 校验失败: {e}", exc_info=True)
                        return None, None
                else:
                    elapsed = int(time.time() - start_time)
                    minutes = elapsed // 60  # 整除60得到分钟数
                    seconds = elapsed % 60   # 取余60得到剩余秒数
                    if elapsed - last_alert_time >= vaa_alert_interval and elapsed >= vaa_alert_timeout:
                        logger.warning(f"等待带payload的VAA已超过 {minutes} 分 {seconds} 秒...")
                        last_alert_time = elapsed
                    sleep_with_log(vaa_poll_interval, logger)
            else:
                logger.error(f"WormholeScan API响应状态码异常: {resp.status_code}，响应内容: {resp.text}")
                sleep_with_log(vaa_poll_interval, logger)
            if vaa and parsed_payload:
                break
        except Exception as e:
            logger.error(f"轮询VAA时发生异常（网络/解析等问题）: {str(e)}", exc_info=True)
            sleep_with_log(vaa_poll_interval, logger)
    return vaa, parsed_payload

# ========== 新增：目标链VAA幂等性检查和赎回函数 ==========
def check_and_redeem_on_dst(config, logger, w3_dst, dst, vaa, account, private_key, src_tx_hash):
    """
    检查VAA是否已在目标链执行，未执行则依次对每个transceiver调用receiveMessage方法进行赎回
    """
    wormholescan_api_base = config["runtime"]["wormholescan_api_base"]
    wormhole_dst_chain_id = dst["wormhole_chain_id"]
    found_completed = False
    try:
        response = requests.get(
            f"{wormholescan_api_base}/live-tracking/subscribe?txHash={src_tx_hash}",
            headers={"accept": "application/json"},
            stream=True,
            timeout=10
        )
    except Exception as e:
        logger.warning(f"Live tracking 请求异常：{e}. 将直接尝试claim")
        response = None

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
                        logger.info("Live tracking 读取超时，将尝试继续执行claim")
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
        return True
    else:
        logger.info("VAA尚未在目标链执行，将进行 claim 操作")

    # 依次对每个transceiver调用receiveMessage方法
    encodedVm_bytes = base64.b64decode(vaa)
    logger.info("VAA已完成Base64解码，准备构建交易")

    for transceiver_cfg in dst["transceivers"]:
        with open(transceiver_cfg["abi_path"], "r") as f:
            transceiver_abi = json.load(f)
        transceiver = w3_dst.eth.contract(address=checksum(transceiver_cfg["address"]), abi=transceiver_abi)
        method = getattr(transceiver.functions, transceiver_cfg["method"])
        nonce = w3_dst.eth.get_transaction_count(account.address)
        tx_dict = method(encodedVm_bytes).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 800000
        })
        tx_dict = build_tx_with_gas_params(w3_dst, tx_dict, logger)
        signed = w3_dst.eth.account.sign_transaction(tx_dict, private_key)
        tx_hash = w3_dst.eth.send_raw_transaction(signed.raw_transaction)
        logger.info(f"目标链 transceiver {transceiver_cfg['name']} claim交易已发送: {tx_hash.hex()}")
        w3_dst.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"目标链 transceiver {transceiver_cfg['name']} claim交易已上链")
    return False

# ========== 结果确认主流程（保持原有实现） ==========
def confirm_result(config, w3_src, w3_dst, logger, digest=None):
    """
    统一的结果确认流程，适用于所有模式
    """
    dst = config["dst"]
    transfer_params = config["transfer_params"]
    ntt_manager_cfg = dst["ntt_manager"]
    methods = ntt_manager_cfg["methods"]
    amount = Decimal(transfer_params["amount"])
    src_chain_id = config["src"]["wormhole_chain_id"]
    private_key = os.getenv(config["auth"]["private_key_env"])
    account = w3_src.eth.account.from_key(private_key)
    from_address = account.address

    # 加载manager合约
    with open(ntt_manager_cfg["abi_path"], "r") as f:
        manager_abi = f.read()
    manager = w3_dst.eth.contract(address=checksum(ntt_manager_cfg["address"]), abi=manager_abi)

    # 确保digest是bytes32格式（bytes类型）
    if isinstance(digest, str):
        if digest.startswith('0x'):
            digest_bytes32 = Web3.to_bytes(hexstr=digest)
        else:
            digest_bytes32 = Web3.to_bytes(hexstr=f"0x{digest}")
    elif isinstance(digest, bytes):
        digest_bytes32 = digest
    else:
        logger.error(f"未知的digest类型: {type(digest)}")
        return

    logger.info(f"使用digest (bytes32格式, 长度: {len(digest_bytes32)}): 0x{digest_bytes32.hex()}")

    # 1. transceiverAttestedToMessage 检查
    logger.info("开始检查所有transceiver的attestation状态...")
    attested_ok = False
    for attempt in range(3):
        all_attested = True
        for transceiver_cfg in dst["transceivers"]:
            idx = transceiver_cfg["index"]
            try:
                # 注意参数顺序：digest, index
                attested = getattr(manager.functions, methods["transceiverAttestedToMessage"])(
                    digest_bytes32, idx
                ).call()
                logger.info(f"transceiver index={idx} attested={attested}")
                if not attested:
                    all_attested = False
            except Exception as e:
                logger.error(f"查询transceiverAttestedToMessage失败: {e}")
                all_attested = False
        if all_attested:
            attested_ok = True
            break
        else:
            logger.warning(f"有transceiver未attest，10秒后重试({attempt+1}/3)...")
            sleep_with_log(10, logger)
    if not attested_ok:
        logger.error("部分transceiver未attest，流程异常终止！")
        return

    # 2. isMessageExecuted 检查
    logger.info("检查消息是否已在目标链执行...")
    try:
        executed = getattr(manager.functions, methods["isMessageExecuted"])(digest_bytes32).call()
        logger.info(f"isMessageExecuted: {executed}")
        if executed:
            logger.info("跨链流程已完成，流程结束。")
            return
    except Exception as e:
        logger.error(f"调用isMessageExecuted失败: {e}")
        return

    # 3. getInboundQueuedTransfer 检查
    logger.info("检查消息是否在入站队列...")
    found_valid_queue = False
    for attempt in range(3):
        try:
            queued_info = getattr(manager.functions, methods["getInboundQueuedTransfer"])(digest_bytes32).call()
            # queued_info结构: (amount, txTimestamp, recipient)
            amount_queued = int(queued_info[0]) if len(queued_info) > 0 else 0
            tx_timestamp = int(queued_info[1]) if len(queued_info) > 1 else 0
            recipient = queued_info[2] if len(queued_info) > 2 else "0x0000000000000000000000000000000000000000"
            logger.info(f"getInboundQueuedTransfer返回: amount={amount_queued}, txTimestamp={tx_timestamp}, recipient={recipient}")
            # 判断是否全为0（空队列），否则为有效
            if amount_queued == 0 and tx_timestamp == 0 and (recipient.lower() == "0x0000000000000000000000000000000000000000" or int(recipient, 16) == 0):
                logger.warning("入站队列为空，10秒后重试({}/{})...".format(attempt+1, 3))
                sleep_with_log(10, logger)
            else:
                found_valid_queue = True
                break
        except Exception as e:
            logger.error(f"调用getInboundQueuedTransfer失败: {e}")
            sleep_with_log(10, logger)
    if not found_valid_queue:
        logger.error("未在入站队列找到有效消息，流程异常终止！")
        return
 
    # 4. getInboundLimitParams 检查
    logger.info("开始轮询入站速率限制参数...")
    while True:
        try:
            limit_info = getattr(manager.functions, methods["getInboundLimitParams"])(src_chain_id).call()
            # limit_info结构: (limit, currentCapacity, lastTxTimestamp)
            limit = Decimal(limit_info[0]) if len(limit_info) > 0 else Decimal(0)
            current_capacity = Decimal(limit_info[1]) if len(limit_info) > 1 else Decimal(0)
            last_tx_timestamp = int(limit_info[2]) if len(limit_info) > 2 else 0
            logger.info(f"当前入站额度: limit={limit}, currentCapacity={current_capacity}, lastTxTimestamp={last_tx_timestamp}，用户跨链数量: {amount}")
            # 只有limit和currentCapacity都大于等于amount时才进入下一步
            if limit >= amount and current_capacity >= amount:
                logger.info("额度充足，准备完成入站队列转账。")
                break
            else:
                logger.info("额度不足，30秒后重试...")
                sleep_with_log(30, logger)
        except Exception as e:
            logger.error(f"调用getInboundLimitParams失败: {e}")
            sleep_with_log(30, logger)

    # 5. completeInboundQueuedTransfer
    logger.info("调用completeInboundQueuedTransfer完成入站转账...")
    try:

        tx = getattr(manager.functions, methods["completeInboundQueuedTransfer"])(digest_bytes32).build_transaction({
            "from": from_address,
            "nonce": w3_dst.eth.get_transaction_count(from_address),
            "gas": 800000
        })
        tx = build_tx_with_gas_params(w3_dst, tx, logger)
        signed = w3_dst.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = w3_dst.eth.send_raw_transaction(signed.rawTransaction)
        logger.info(f"completeInboundQueuedTransfer已提交，tx_hash: {tx_hash.hex()}")
        receipt = w3_dst.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"completeInboundQueuedTransfer上链成功，区块号: {receipt.blockNumber}")
    except Exception as e:
        logger.error(f"completeInboundQueuedTransfer提交失败: {e}")
        return

    # 6. 再次检查isMessageExecuted
    try:
        executed = getattr(manager.functions, methods["isMessageExecuted"])(digest_bytes32).call()
        logger.info(f"最终isMessageExecuted: {executed}")
        if executed:
            logger.info("跨链流程已全部完成。")
        else:
            logger.warning("completeInboundQueuedTransfer后消息仍未执行，请人工检查。")
    except Exception as e:
        logger.error(f"最终isMessageExecuted查询失败: {e}")

# ========== 主流程 ==========

def main():
    """
    跨链主流程，包含配置加载、授权、发起跨链、拉取VAA、目标链赎回、状态确认等步骤
    """
    # 1. 加载配置和私钥
    config = load_config()
    load_dotenv()
    logger = setup_logger(config["logging"]["log_level"], config["logging"]["log_file"])
    logger.info("配置和日志系统加载完成。")

    mode = config["mode"]
    src = config["src"]
    dst = config["dst"]
    token = config["token"]
    transfer_params = config["transfer_params"]
    private_key = os.getenv(config["auth"]["private_key_env"])
    src_tx_hash = config.get("src_tx_hash", "")

    # 2. 初始化web3（传入is_poa参数），默认False（兼容未配置的情况）
    w3_src = init_web3(src["rpc"], enable_poa_middleware=src.get("is_poa", False))
    w3_dst = init_web3(dst["rpc"], enable_poa_middleware=dst.get("is_poa", False))
    account = w3_src.eth.account.from_key(private_key)
    logger.info(f"使用账户: {account.address}")

    erc20_abi = [
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
    erc20 = w3_src.eth.contract(address=checksum(token["address_on_src"]), abi=erc20_abi)
    min_unit_amount = amount_to_min_unit(transfer_params["amount"], token["decimals"])


    # ========== full_send模式 ==========
    if mode == "full_send":
        # 3. 检查余额和授权
        balance = erc20.functions.balanceOf(account.address).call()
        human_balance = Decimal(balance) / Decimal(10 ** token["decimals"])
        logger.info(f"当前余额: {human_balance} {token['symbol']}")
        logger.info(f"跨链代币数量: {transfer_params['amount']} {token['symbol']}")
        if balance < min_unit_amount:
            logger.error("余额不足，无法跨链")
            sys.exit(1)

        # 检查授权（approve），如需则发起授权交易
        if token.get("approve_required", True) and mode == "full_send":
            allowance = erc20.functions.allowance(account.address, checksum(src["ntt_manager"]["address"])).call()
            if allowance < min_unit_amount:
                logger.info("开始授权 manager 合约...")
                approve_tx = erc20.functions.approve(checksum(src["ntt_manager"]["address"]), min_unit_amount)
                nonce = w3_src.eth.get_transaction_count(account.address)
                tx_dict = approve_tx.build_transaction({
                    "from": account.address,
                    "nonce": nonce,
                    "gas": 100000
                })
                tx_dict = build_tx_with_gas_params(w3_src, tx_dict, logger)
                signed = w3_src.eth.account.sign_transaction(tx_dict, private_key)
                tx_hash = w3_src.eth.send_raw_transaction(signed.raw_transaction)
                logger.info(f"授权交易已发送: {tx_hash.hex()}")
                w3_src.eth.wait_for_transaction_receipt(tx_hash)
                logger.info("授权完成")

        # 4. 发起跨链
        with open(src["ntt_manager"]["abi_path"], "r") as f:
            manager_abi = json.load(f)
        manager = w3_src.eth.contract(address=checksum(src["ntt_manager"]["address"]), abi=manager_abi)
        method = getattr(manager.functions, src["ntt_manager"]["method"])
        recipient_bytes32 = to_bytes32(transfer_params["recipient"])
        refund_address_bytes32 = to_bytes32(transfer_params["refund_address"])
        params = [           # 需要根据实际方法参数调整顺序
            min_unit_amount,
            transfer_params["recipient_wormhole_chain"],
            recipient_bytes32,
            refund_address_bytes32,
            transfer_params["should_queue"],
            Web3.to_bytes(hexstr=transfer_params["transceiver_instructions_hex"])
        ]
        recipient_chain = transfer_params["recipient_wormhole_chain"]
        instructions_bytes = Web3.to_bytes(
            hexstr=transfer_params["transceiver_instructions_hex"]
        )
        _, total_delivery_price = manager.functions.quoteDeliveryPrice(
            recipient_chain,
            instructions_bytes
        ).call()
        nonce = w3_src.eth.get_transaction_count(account.address)
        tx_dict = method(*params).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 500000,
            "value": total_delivery_price
        })
        tx_dict = build_tx_with_gas_params(w3_src, tx_dict, logger)
        signed = w3_src.eth.account.sign_transaction(tx_dict, private_key)
        tx_hash = w3_src.eth.send_raw_transaction(signed.raw_transaction)
        logger.info(f"跨链交易已发送: {tx_hash.hex()}")
        w3_src.eth.wait_for_transaction_receipt(tx_hash)
        logger.info("跨链交易已上链")
        src_tx_hash = tx_hash.hex()

        # 5. 轮询VAA并校验
        logger.info("开始轮询 WormholeScan 获取 VAA...")
        vaa, parsed_payload = poll_and_validate_vaa(
            config, logger, src_tx_hash, min_unit_amount,
            transfer_params["recipient"], dst["wormhole_chain_id"], token
        )
        if not vaa:
            logger.error("VAA获取或校验失败，流程终止。")
            return

        # 6. 幂等性检查和7. 目标链赎回
        found_completed = check_and_redeem_on_dst(config, logger, w3_dst, dst, vaa, account, private_key, src_tx_hash)
        if found_completed:
            return

        # 8. 结果确认
        digest = None
        for attempt in range(3):
            digest = get_digest_from_src_tx(w3_src, src_tx_hash, logger)
            if digest:
                break
            logger.warning(f"未获取到digest，10秒后重试({attempt+1}/3)...")
            sleep_with_log(10, logger)
        if not digest:
            logger.error("无法获取digest，流程终止。")
            return
        confirm_result(config, w3_src, w3_dst, logger, digest)

    # ========== redeem_only模式 ==========
    elif mode == "redeem_only":
        
        # 5. 轮询VAA并校验
        logger.info("开始轮询 WormholeScan 获取 VAA...")
        vaa, parsed_payload = poll_and_validate_vaa(
            config, logger, src_tx_hash, min_unit_amount,
            transfer_params["recipient"], dst["wormhole_chain_id"], token
        )
        if not vaa:
            logger.error("VAA获取或校验失败，流程终止。")
            return

        # 6. 幂等性检查和7. 目标链赎回
        src_tx_hash = config.get("src_tx_hash", "")
        found_completed = check_and_redeem_on_dst(config, logger, w3_dst, dst, vaa, account, private_key, src_tx_hash)
        if found_completed:
            return

        # 8. 结果确认
        digest = None
        for attempt in range(3):
            digest = get_digest_from_src_tx(w3_src, src_tx_hash, logger)
            if digest:
                break
            logger.warning(f"未获取到digest，10秒后重试({attempt+1}/3)...")
            sleep_with_log(10, logger)
        if not digest:
            logger.error("无法获取digest，流程终止。")
            return
        confirm_result(config, w3_src, w3_dst, logger, digest)

    # ========== complete_inbound模式 ==========
    elif mode == "complete_inbound":
        # 8. 结果确认
        digest = config.get("digest")
        if not digest:
            # 如果配置文件没有digest，则尝试用src_tx_hash获取
            if not src_tx_hash:
                logger.error("complete_inbound模式下digest和src_tx_hash均未配置，无法获取digest，流程终止。")
                return
            for attempt in range(3):
                digest = get_digest_from_src_tx(w3_src, src_tx_hash, logger)
                if digest:
                    break
                logger.warning(f"未获取到digest，10秒后重试({attempt+1}/3)...")
                sleep_with_log(10, logger)
            if not digest:
                logger.error("无法获取digest，流程终止。")
                return
        confirm_result(config, w3_src, w3_dst, logger, digest)

if __name__ == "__main__":
    main()
