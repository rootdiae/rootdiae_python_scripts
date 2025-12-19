import os
import sys
import time
import json
import base64
import logging
import requests
import yaml  #安的不是这个库，是pip install pyyaml -i https://pypi.tuna.tsinghua.edu.cn/simple
from decimal import Decimal, getcontext
from web3 import Web3
from dotenv import load_dotenv
from web3.middleware import ExtraDataToPOAMiddleware

# 添加poa中间件，修改构建交易参数的fee逻辑，增加对baseFeePerGas为0的处理
# 目标链可以成功claim，但是还是需增加检查：对于多阈值的manager，
# 需要判断是否满足transceivers验证阈值，调用isMessageApproved方法；
# 需要判断是否卡在队列中，调用getInboundQueuedTransfer方法。
# 输入参数digest从源链的交易event logs里获取

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
    构建交易参数，优先使用EIP-1559格式（maxFeePerGas和maxPriorityFeePerGas），
    如果失败则回退到传统gasPrice格式。
    
    新增逻辑：
    1. 当baseFeePerGas为0时，EIP-1559参数无效，回退到gasPrice模式
    2. 当maxFeePerGas或maxPriorityFeePerGas为0时，EIP-1559参数无效，回退到gasPrice模式
    3. 回退到gasPrice模式时，清除EIP-1559相关参数，避免冲突
    """
    tx = tx_dict.copy()
    chain_id = w3.eth.chain_id
    tx["chainId"] = chain_id
    try:
        # 获取最新区块的baseFeePerGas
        fee_data = w3.eth.fee_history(1, 'latest')
        base_fee = int(fee_data['baseFeePerGas'][-1])
        
        # ========== 新增检查：baseFeePerGas为0表示EIP-1559不支持或链未启用 ==========
        if base_fee == 0:
            logger.warning(f"baseFeePerGas为{base_fee}，该链可能不支持EIP-1559或处于0gas费环境，回退到gasPrice模式")
            raise ValueError("baseFeePerGas is zero, fallback to gasPrice mode")
        
        # 获取最大优先费
        max_priority_fee = int(w3.eth.max_priority_fee)
        
        # 计算最大总费用（基础费用的1.2倍）
        max_fee_per_gas = int(base_fee * 1.2)
        
        # ========== 新增检查：maxFeePerGas为0时回退 ==========
        if max_fee_per_gas == 0:
            logger.warning(f"计算出的maxFeePerGas为{max_fee_per_gas}，回退到gasPrice模式")
            raise ValueError("maxFeePerGas is zero, fallback to gasPrice mode")
        
        # 优先费不能过高
        if max_priority_fee > max_fee_per_gas * 0.5:
            max_priority_fee = max_fee_per_gas // 10
        
        # ========== 新增检查：maxPriorityFeePerGas为0时回退 ==========
        if max_priority_fee == 0:
            logger.warning(f"计算出的maxPriorityFeePerGas为{max_priority_fee}，回退到gasPrice模式")
            raise ValueError("maxPriorityFeePerGas is zero, fallback to gasPrice mode")
        
        # 设置EIP-1559参数，并确保清除可能存在的gasPrice参数
        tx["maxFeePerGas"] = max_fee_per_gas
        tx["maxPriorityFeePerGas"] = max_priority_fee
        if "gasPrice" in tx:
            del tx["gasPrice"]  # 移除gasPrice，避免与EIP-1559参数冲突
        logger.info(f"使用EIP-1559参数构建交易: maxFeePerGas={max_fee_per_gas}, maxPriorityFeePerGas={max_priority_fee}")
        return tx
    except Exception as e:
        # 捕获所有异常（包括我们主动抛出的ValueError）并回退到传统gasPrice模式
        logger.warning(f"EIP-1559参数无效或获取失败: {e}，尝试使用传统gasPrice参数")
        try:
            gas_price = w3.eth.gas_price
            tx["gasPrice"] = gas_price
            # ========== 新增：回退到gasPrice模式时，清除所有EIP-1559参数 ==========
            if "maxFeePerGas" in tx:
                del tx["maxFeePerGas"]
            if "maxPriorityFeePerGas" in tx:
                del tx["maxPriorityFeePerGas"]
            logger.info(f"使用传统gasPrice构建交易: gasPrice={gas_price}")
            return tx
        except Exception as ee:
            logger.error(f"获取gasPrice失败: {ee}，无法构建交易参数")
            raise

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
    wormholescan_api_base = config["runtime"]["wormholescan_api_base"]
    vaa_poll_interval = float(config["runtime"]["vaa_poll_interval_seconds"])
    vaa_alert_interval = int(config["runtime"]["vaa_alert_interval_seconds"])
    vaa_alert_timeout = int(config["runtime"]["vaa_alert_timeout_seconds"])
    src_tx_hash = config.get("src_tx_hash", "")


    # 2. 初始化web3（传入is_poa参数）
    # 从配置读取src/dst的is_poa标识，默认False（兼容未配置的情况）
    w3_src = init_web3(src["rpc"], enable_poa_middleware=src.get("is_poa", False))
    w3_dst = init_web3(dst["rpc"], enable_poa_middleware=dst.get("is_poa", False))
    account = w3_src.eth.account.from_key(private_key)
    logger.info(f"使用账户: {account.address}")

    # 3. 检查余额和授权
    # 构造ERC20合约对象
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

    # 4. full_send模式下发起跨链
    if mode == "full_send":
        # 加载manager合约ABI
        with open(src["ntt_manager"]["abi_path"], "r") as f:
            manager_abi = json.load(f)
        manager = w3_src.eth.contract(address=checksum(src["ntt_manager"]["address"]), abi=manager_abi)
        method = getattr(manager.functions, src["ntt_manager"]["method"])
        recipient_bytes32 = to_bytes32(transfer_params["recipient"])
        refund_address_bytes32 = to_bytes32(transfer_params["refund_address"])
        # 发起跨链交易所需参数（实际参数顺序需与ABI一致）
        params = [
            min_unit_amount,  # 转账金额（uint256类型）
            transfer_params["recipient_wormhole_chain"],  # 目标链Wormhole chain id（uint16类型）
            recipient_bytes32,  #  接收地址（bytes32格式）
            refund_address_bytes32,  # 退款地址（bytes32格式）
            transfer_params["should_queue"],  # 是否排队（bool类型）
            Web3.to_bytes(hexstr=transfer_params["transceiver_instructions_hex"])  # 收发器指令（hex字符串转bytes类型）
        ]
        # === 新增：quoteDeliveryPrice ===
        recipient_chain = transfer_params["recipient_wormhole_chain"]
        instructions_bytes = Web3.to_bytes(
            hexstr=transfer_params["transceiver_instructions_hex"]
        )

        _, total_delivery_price = manager.functions.quoteDeliveryPrice(
            recipient_chain,
            instructions_bytes
        ).call()

        # 构建并发送交易
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

    # 5. 轮询 WormholeScan 获取 VAA 并校验
    logger.info("开始轮询 WormholeScan 获取 VAA...")
    vaa = None
    parsed_payload = None
    start_time = time.time()
    last_alert_time = 0
    recipient_on_dst = transfer_params["recipient"]
    wormhole_dst_chain_id = dst["wormhole_chain_id"]
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
                        # ========== 核心修正：按正确路径解析字段 ==========
                        # 逐层获取字段，增加空值检查
                        ntt_message = parsed_payload.get("nttMessage", {})
                        trimmed_amount = ntt_message.get("trimmedAmount", {})
                        
                        # 1. 校验金额（修复路径+空值检查）
                        amount_str = trimmed_amount.get("amount")
                        if amount_str is None:
                            logger.error("VAA 校验失败：未找到 trimmedAmount.amount 字段")
                            return
                        # 校验trimmedAmount的decimals是否为8（WTT约定）
                        trimmed_decimals = trimmed_amount.get("decimals")
                        if trimmed_decimals != 8:
                            logger.error(f"VAA 校验失败：trimmedAmount.decimals 不是8，实际为 {trimmed_decimals}")
                            return
                        # 金额转换（保持原逻辑）
                        normalized_amount = int(amount_str)
                        scale = 10 ** (token["decimals"] - 8)
                        reconstructed_amount = normalized_amount * scale
                        if str(reconstructed_amount) != str(min_unit_amount):
                            logger.error(f"VAA 金额校验失败：解析值 {reconstructed_amount} vs 预期值 {min_unit_amount}")
                            return
                        else:
                            # 计算十进制金额（最小单位转正常显示）
                            token_decimals = token["decimals"]
                            decimal_amount = Decimal(min_unit_amount) / (10 ** token_decimals)
                            decimal_amount = decimal_amount.normalize()
                            # 打印人性化的十进制金额
                            logger.info(f"VAA金额校验成功: {decimal_amount} {token['symbol']} (最小单位: {min_unit_amount})")
                        
                        # 2. 校验接收地址（修复路径+空值检查）
                        to_address = ntt_message.get("to", "")
                        if not to_address:
                            logger.error("VAA 校验失败：未找到 nttMessage.to 字段")
                            return
                        # 只对比后40位（兼容不同格式的地址）
                        if to_address.lower()[-40:] != recipient_on_dst.lower()[-40:]:
                            logger.error(f"VAA 接收地址校验失败：解析值 {to_address} vs 预期值 {recipient_on_dst}")
                            return
                        else:
                            logger.info(f"VAA地址校验成功: {to_address}")
                        
                        # 3. 校验目标链ID（修复路径+空值检查）
                        to_chain = ntt_message.get("toChain")
                        if to_chain is None:
                            logger.error("VAA 校验失败：未找到 nttMessage.toChain 字段")
                            return
                        if int(to_chain) != wormhole_dst_chain_id:
                            logger.error(f"VAA 目标链ID校验失败：解析值 {to_chain} vs 预期值 {wormhole_dst_chain_id}")
                            return
                        else:
                            logger.info(f"VAA目标链ID校验成功: {to_chain}")
                        
                        logger.info("VAA 所有校验通过")
                        break
                    except Exception as e:
                        logger.error(f"VAA 校验失败: {e}", exc_info=True)  # 打印完整栈信息，方便调试
                        return
                else:
                    # 没有找到带payload的VAA，继续轮询
                    elapsed = int(time.time() - start_time)
                    if elapsed - last_alert_time >= vaa_alert_interval and elapsed >= vaa_alert_timeout:
                        logger.warning(f"等待带payload的VAA已超过 {elapsed} 秒...")
                        last_alert_time = elapsed
                    sleep_with_log(vaa_poll_interval, logger)
            else:
                # 响应状态码非200，属于异常情况
                logger.error(f"WormholeScan API响应状态码异常: {resp.status_code}，响应内容: {resp.text}")
                sleep_with_log(vaa_poll_interval, logger)  # 异常时也休眠，避免高频请求
            # 若找到VAA则退出循环
            if vaa and parsed_payload:
                break
        except Exception as e:
            # 捕获网络异常、JSON解析失败等情况，区分于数据为空的正常情况
            logger.error(f"轮询VAA时发生异常（网络/解析等问题）: {str(e)}", exc_info=True)
            sleep_with_log(vaa_poll_interval, logger)  # 异常时休眠，避免死循环

    # 6. 幂等性检查
    logger.info("检查 VAA 是否已在目标链执行...")
    found_completed = False
    try:
        # 通过live-tracking接口订阅VAA状态
        response = requests.get(
            f"{wormholescan_api_base}/live-tracking/subscribe?txHash={src_tx_hash}",
            headers={"accept": "application/json"},
            stream=True,
            timeout=10
        )
    except Exception as e:
        logger.warning(f"Live tracking 请求异常：{e}. 将直接尝试赎回。")
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

    # 7. 目标链提交 VAA
    # 依次对每个transceiver调用receiveMessage方法
    # 将Base64编码的VAA解码为字节数据
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
        logger.info(f"目标链 transceiver {transceiver_cfg['name']} 赎回交易已发送: {tx_hash.hex()}")
        w3_dst.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"目标链 transceiver {transceiver_cfg['name']} 赎回交易已上链")

    # 8. 结果确认
    # 调用目标链manager的transceiverAttestedToMessage方法，确认attestation状态
    with open(dst["ntt_manager"]["abi_path"], "r") as f:
        manager_abi = json.load(f)
    manager = w3_dst.eth.contract(address=checksum(dst["ntt_manager"]["address"]), abi=manager_abi)
    digest = Web3.keccak(encodedVm_bytes)
    attested = getattr(manager.functions, dst["ntt_manager"]["method"])(digest, checksum(dst["transceivers"][0]["address"])).call()
    if attested:
        logger.info("目标链 manager attestation 达到阈值，等待ntt manager处理跨链完成")
    else:
        logger.warning("目标链 manager attestation 未达阈值，请检查 transceiver 配置或稍后重试")

if __name__ == "__main__":
    main()