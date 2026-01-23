import os
import sys
import re
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional, Union  # 显式导入兼容类型注解
# 安全三方库（均为官方/高可信度）
from web3 import Web3
from web3.exceptions import Web3Exception
import eth_utils

# 此脚本用于构造可直接提交交易的Metadata：messageid/merkleroot格式
# 输入为验证者签名列表、阈值、索引、类型等，输出为十六进制字符串格式的Metadata。签名拼接顺序需与验证者列表顺序一致。验证者列表顺序来自于ism合约查询到的原始顺序。


# ======================== 【第一步：全局日志配置 - 核心必配，控制台+文件双输出】 ========================
def init_logger() -> logging.Logger:
    """
    初始化日志配置，满足要求：统一使用logging、日志清晰、输出控制台+文件、分级打印
    日志级别说明：DEBUG-调试细节(参数/转换结果)、INFO-流程进度、WARNING-非致命警告、ERROR-致命错误(终止运行)
    """
    logger = logging.getLogger("HyperlaneMetadataBuilder")
    logger.setLevel(logging.DEBUG)  # 总级别为DEBUG，输出所有日志
    logger.handlers.clear()  # 清空重复处理器

    # 日志格式：时间 | 日志级别 | 模块 | 具体信息
    log_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(module)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 1. 控制台处理器 - 输出INFO及以上日志（简洁，适合运行查看）
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(log_formatter)

    # 2. 文件处理器 - 输出DEBUG及以上日志（详尽，适合问题定位，文件保存在当前目录）
    file_handler = logging.FileHandler("metadata_builder.log", encoding="utf-8", mode="a")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(log_formatter)

    # 添加处理器
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger

# 初始化全局日志对象
logger = init_logger()

# ======================== 【第二步：Hyperlane官方硬编码常量 - 不可修改，源码对标】 ========================
class HyperlaneConst:
    """Hyperlane核心常量定义，100%对标官方源码"""
    TREE_DEPTH = 32  # Merkle树固定深度，源码硬编码
    PROOF_BYTES_LENGTH = TREE_DEPTH * 32  # MerkleProof固定长度 1024字节
    U32_BYTE_LENGTH = 4  # u32类型固定字节长度，大端序
    U32_MAX_VALUE = 4294967295  # u32最大值 2^32-1
    SIGNATURE_BYTES_LENGTH = 65  # 单个Validator签名固定长度 r(32)+s(32)+v(1)
    H256_BYTES_LENGTH = 32  # H256哈希/地址固定字节长度
    ETH_ADDR_BYTES_LENGTH = 20  # 原生以太坊地址长度
    METADATA_TYPE_MSG_ID = "messageid"  # 轻量化类型标识
    METADATA_TYPE_MERKLE_ROOT = "merkleroot"  # 完整版类型标识
    VALID_V_VALUES = [27, 28]  # 合法的签名v值
    V_MAP = {27: "1b", 28: "1c"}  # v值与serialized_signature末尾字符的映射

# ======================== 【第三步：输入配置参数 - 内置完整示例，直接运行】 ========================
INPUT_CONFIG = {
    "validator_signatures": [
        {
            "value": {
                "checkpoint": {
                    "merkle_tree_hook_address": "0x00000000000000000000000019dc38aeae620380430c200a6e990d5af5480117",
                    "mailbox_domain": 8453,
                    "root": "0xd0da44bb893ca80c15cb8206bcd7a7ff3aab635bed0ba32799d00b2bdfb30b84",
                    "index": 1498599
                },
                "message_id": "0xad83200ad99a5dad2fddccb12e6d646b4998a7aa27152347e2b05cf4a411b158"
            },
            "signature": {
                "r": "0x5a3307ef9c3ec9259cdcc3c572ab6997bbe0890f6fddc8ed16cf008c60988b61",
                "s": "0xeb301c259613ac4fad63696c423211b50419b56e4e2dcb3550bd58d32184055",
                "v": 27
            },
            "serialized_signature": "0x5a3307ef9c3ec9259cdcc3c572ab6997bbe0890f6fddc8ed16cf008c60988b610eb301c259613ac4fad63696c423211b50419b56e4e2dcb3550bd58d321840551b"
        },
        {
            "value": {
                "checkpoint": {
                    "merkle_tree_hook_address": "0x00000000000000000000000019dc38aeae620380430c200a6e990d5af5480117",
                    "mailbox_domain": 8453,
                    "root": "0x37eba5cd89770ad4908b915d345e050c252341f3e9d2ae2f1a1bf281ff72e6d4",
                    "index": 1498599
                },
                "message_id": "0xad83200ad99a5dad2fddccb12e6d646b4998a7aa27152347e2b05cf4a411b158"
            },
            "signature": {
                "r": "0x339cda0341e33cd9b774cc4273cd0e69f38c8a1406eeef1e1b84f999fd7d5e97",
                "s": "0x279f1ec07dd297869a37caffd80e8d6c88d50e2d25afa82b3cbfb4b7df9ffbb5",
                "v": 27
            },
            "serialized_signature": "0x339cda0341e33cd9b774cc4273cd0e69f38c8a1406eeef1e1b84f999fd7d5e97279f1ec07dd297869a37caffd80e8d6c88d50e2d25afa82b3cbfb4b7df9ffbb51b"
        },
        {
            "value": {
                "checkpoint": {
                    "merkle_tree_hook_address": "0x00000000000000000000000019dc38aeae620380430c200a6e990d5af5480117",
                    "mailbox_domain": 8453,
                    "root": "0xffe36d7917d21adcfad94a5bf395c4220f327f62083dce26d5b149fcc5d1e22c",
                    "index": 1498599
                },
                "message_id": "0xad83200ad99a5dad2fddccb12e6d646b4998a7aa27152347e2b05cf4a411b158"
            },
            "signature": {
                "r": "0xe9bddd95825ec048c1b08b58c79afe28f14db3a204d6320535aca08cc1596163",
                "s": "0x5ac9c9458dd5798a60d910410d47afd9277177294c63aaad9b646e3838aed35c",
                "v": 28
            },
            "serialized_signature": "0xe9bddd95825ec048c1b08b58c79afe28f14db3a204d6320535aca08cc15961635ac9c9458dd5798a60d910410d47afd9277177294c63aaad9b646e3838aed35c1c"
        }
    ],  # 按照validators_and_threshold返回的验证者的顺序填写签名
    "threshold": 1,  # 验证人阈值（≤签名数量）
    "merkle_tree_index": 156303,  # 消息叶子索引（合法u32）
    "rpc_nodes": [  # 多RPC节点池（自动重试)
        "https://base.meowrpc.com",
        "https://base.drpc.org",
        "https://mainnet.base.org"
    ],
    "metadata_type": HyperlaneConst.METADATA_TYPE_MERKLE_ROOT,  # 构造类型：messageid/merkleroot
    "merkletreehook_abi": [
        {
            "inputs": [],
            "name": "tree",
            "outputs": [
                {
                    "components": [
                        {"internalType": "bytes32[32]", "name": "branch", "type": "bytes32[32]"},
                        {"internalType": "uint256", "name": "count", "type": "uint256"}
                    ],
                    "internalType": "struct MerkleLib.Tree",
                    "name": "",
                    "type": "tuple"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "root",
            "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "count",
            "outputs": [{"internalType": "uint32", "name": "", "type": "uint32"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]
}

# ======================== 【第四步：核心工具函数 - 新增地址转换，修复核心错误】 ========================
def hex_to_bytes(hex_str: str, expected_len: Optional[int] = None) -> bytes:
    """
    安全的十六进制字符串转bytes（Hyperlane核心转换工具）
    :param hex_str: 0x开头的十六进制字符串（地址/哈希/签名）
    :param expected_len: 期望的bytes长度（None则不校验）
    :return: 合规的bytes对象
    :raise ValueError: 格式/长度错误时抛出异常
    """
    if not isinstance(hex_str, str):
        raise ValueError(f"十六进制字符串必须为str类型，当前类型: {type(hex_str)}")
    if not hex_str.startswith("0x"):
        raise ValueError(f"十六进制字符串必须以0x开头，当前值: {hex_str}")
    clean_hex = hex_str[2:].lower()  # 去前缀+转小写
    try:
        res_bytes = bytes.fromhex(clean_hex)
    except ValueError as e:
        raise ValueError(f"十六进制格式错误: {hex_str}, 错误: {str(e)}") from e
    if expected_len is not None and len(res_bytes) != expected_len:
        raise ValueError(f"字节长度不匹配：期望{expected_len}字节，实际{len(res_bytes)}字节（值：{hex_str}）")
    logger.debug(f"十六进制转bytes成功：{hex_str} -> {res_bytes.hex()}（长度：{len(res_bytes)}字节）")
    return res_bytes

def u32_to_big_endian_bytes(num: int) -> bytes:
    """
    u32整数转4字节大端序bytes（对标Hyperlane源码u32::to_be_bytes()）
    :param num: 合法u32整数（0 ≤ num ≤ 4294967295）
    :return: 4字节大端序bytes
    :raise ValueError: 数值越界时抛出异常
    """
    if not isinstance(num, int):
        raise ValueError(f"u32数值必须为int类型，当前类型: {type(num)}")
    if num < 0 or num > HyperlaneConst.U32_MAX_VALUE:
        raise ValueError(f"u32数值越界：合法范围0~{HyperlaneConst.U32_MAX_VALUE}，当前值{num}")
    res_bytes = num.to_bytes(HyperlaneConst.U32_BYTE_LENGTH, byteorder="big", signed=False)
    logger.debug(f"u32转大端序bytes成功：{num} -> {res_bytes.hex()}（固定4字节）")
    return res_bytes

def h256_to_eth_address(h256_addr: str) -> str:
    """
    核心修复：Hyperlane 32字节H256地址转换为20字节以太坊合法地址
    逻辑：截取H256地址最后20字节（40位十六进制字符），转换为checksum地址
    :param h256_addr: 32字节H256格式地址（0x开头，64位字符）
    :return: 20字节以太坊checksum地址
    :raise ValueError: 地址格式非法时抛出异常
    """
    logger.info(f"开始转换H256地址为以太坊合法地址：原始地址 {h256_addr}")
    # 1. 校验原始地址格式
    if not h256_addr.startswith("0x") or len(h256_addr) != 66:  # 0x + 64位字符 = 66位
        raise ValueError(f"H256地址格式非法，必须是0x开头且长度为66位，当前值：{h256_addr}（长度{len(h256_addr)}）")
    # 2. 截取最后20字节（40位字符）
    eth_addr_hex = "0x" + h256_addr[-40:]
    logger.debug(f"截取最后20字节：{eth_addr_hex}")
    # 3. 转换为checksum地址
    try:
        checksum_addr = Web3.to_checksum_address(eth_addr_hex)
    except ValueError as e:
        raise ValueError(f"转换为以太坊checksum地址失败：{str(e)}") from e
    logger.info(f"H256地址转换成功：{h256_addr} -> {checksum_addr}")
    return checksum_addr

def create_web3_client(rpc_nodes: List[str]) -> Web3:
    """
    多RPC节点自动重试创建Web3客户端（容错核心）
    :param rpc_nodes: RPC节点列表（如["https://xxx", ...]）
    :return: 可用的Web3实例
    :raise ConnectionError: 所有节点失败时抛出异常
    """
    if not rpc_nodes or len(rpc_nodes) == 0:
        raise ValueError("RPC节点列表不能为空")
    for idx, rpc_url in enumerate(rpc_nodes, 1):
        try:
            logger.info(f"尝试连接RPC节点 [{idx}/{len(rpc_nodes)}]：{rpc_url}")
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 10}))
            if not w3.is_connected():
                raise Web3Exception("RPC节点未返回连通状态")
            logger.info(f"RPC节点连接成功：{rpc_url}")
            return w3
        except (Web3Exception, ConnectionError, TimeoutError) as e:
            logger.warning(f"RPC节点 [{rpc_url}] 连接失败：{str(e)}，自动重试下一个节点")
            continue
    raise ConnectionError(f"所有{len(rpc_nodes)}个RPC节点连接失败，请检查节点地址/网络")

def calculate_merkle_proof(w3: Web3, hook_addr: str, leaf_index: int, message_id: str) -> bytes:
    """
    离线计算Hyperlane合规1024字节MerkleProof（100%复刻官方源码Proof::new()）
    新增：自动转换H256地址为以太坊合法地址，修复核心错误
    :param w3: 可用Web3实例
    :param hook_addr: MerkleTreeHook合约地址（32字节H256格式）
    :param leaf_index: 消息叶子索引（合法u32）
    :param message_id: 消息ID（0x开头）
    :return: 1024字节MerkleProof bytes
    :raise ValueError: 计算/校验失败时抛出异常
    """
    logger.info("开始计算MerkleProof（Hyperlane增量Merkle树算法，固定1024字节）")
    # 核心修复：转换H256地址为以太坊合法地址
    valid_hook_addr = h256_to_eth_address(hook_addr)
    # 1. 初始化合约实例（使用转换后的合法地址）
    hook_contract = w3.eth.contract(address=valid_hook_addr, abi=INPUT_CONFIG["merkletreehook_abi"])
    # 2. 获取树结构
    try:
        tree_data = hook_contract.functions.tree().call()
    except Web3Exception as e:
        raise ValueError(f"调用MerkleTreeHook合约tree()方法失败：{str(e)}") from e
    tree_branch = tree_data[0]  # 32层节点bytes32数组
    tree_count = tree_data[1]   # 叶子总数
    # 3. 校验索引合法性
    if leaf_index >= tree_count:
        raise ValueError(f"叶子索引{leaf_index}超过树的叶子总数{tree_count}，索引无效")
    # 4. 叶子值 = message_id
    leaf_value = hex_to_bytes(message_id, HyperlaneConst.H256_BYTES_LENGTH)
    # 5. 核心算法：Hyperlane增量Merkle累加器Proof计算
    proof = [b"\x00" * 32] * HyperlaneConst.TREE_DEPTH
    current_index = leaf_index
    current_value = leaf_value
    for i in range(HyperlaneConst.TREE_DEPTH):
        if current_index % 2 == 0:
            sibling = tree_branch[i]
            proof[i] = sibling
            current_value = eth_utils.keccak(current_value + sibling)
        else:
            sibling = tree_branch[i]
            proof[i] = sibling
            current_value = eth_utils.keccak(sibling + current_value)
        current_index = current_index // 2
    # 6. 拼接为1024字节Proof
    proof_bytes = b"".join([bytes.fromhex(s.hex()) for s in proof])
    # 7. 长度校验（必须1024字节）
    if len(proof_bytes) != HyperlaneConst.PROOF_BYTES_LENGTH:
        raise ValueError(f"MerkleProof长度错误：期望1024字节，实际{len(proof_bytes)}字节")
    logger.info(f"MerkleProof计算成功：长度{len(proof_bytes)}字节（固定1024字节）")
    logger.debug(f"MerkleProof十六进制：0x{proof_bytes.hex()}")
    return proof_bytes

def process_and_validate_signatures(sigs: List[Dict], threshold: int) -> Tuple[bytes, str, str, int, str]:
    """
    签名处理+全量合法性校验（对标Hyperlane MetadataBuilder.validate()）
    :param sigs: Validator签名列表
    :param threshold: 验证人阈值
    :return: (签名合集bytes, hook地址, message_id, mailbox_domain, checkpoint_root)
    :raise ValueError: 校验失败时精准提示
    """
    logger.info(f"处理签名列表：总数{len(sigs)}，阈值{threshold}")
    # 基础校验
    if len(sigs) < threshold:
        raise ValueError(f"签名数量({len(sigs)}) < 验证阈值({threshold})，无法构造合规Metadata")
    if threshold < 1:
        raise ValueError(f"验证阈值必须≥1，当前值{threshold}")
    
    # 基准字段（第一个签名）
    base_sig = sigs[0]["value"]
    base_hook_addr = base_sig["checkpoint"]["merkle_tree_hook_address"]
    base_mailbox_domain = base_sig["checkpoint"]["mailbox_domain"]
    base_message_id = base_sig["message_id"]
    base_checkpoint_root = base_sig["checkpoint"]["root"]

    # 校验所有签名的公共字段一致性（Hyperlane强制要求）
    for idx, sig in enumerate(sigs, 1):
        curr_sig = sig["value"]
        # 校验hook地址
        if curr_sig["checkpoint"]["merkle_tree_hook_address"] != base_hook_addr:
            raise ValueError(f"签名{idx} hook地址不一致：基准{base_hook_addr}，当前{curr_sig['checkpoint']['merkle_tree_hook_address']}")
        # 校验mailbox_domain
        if curr_sig["checkpoint"]["mailbox_domain"] != base_mailbox_domain:
            raise ValueError(f"签名{idx} mailbox_domain不一致：基准{base_mailbox_domain}，当前{curr_sig['checkpoint']['mailbox_domain']}")
        # 校验message_id
        if curr_sig["message_id"] != base_message_id:
            raise ValueError(f"签名{idx} message_id不一致：基准{base_message_id}，当前{curr_sig['message_id']}")
        # 校验serialized_signature
        ser_sig = sig["serialized_signature"]
        sig_bytes = hex_to_bytes(ser_sig, HyperlaneConst.SIGNATURE_BYTES_LENGTH)
        # 校验v值匹配
        v_val = sig["signature"]["v"]
        if v_val not in HyperlaneConst.VALID_V_VALUES:
            raise ValueError(f"签名{idx} v值非法：合法值{HyperlaneConst.VALID_V_VALUES}，当前{v_val}")
        if not ser_sig.endswith(HyperlaneConst.V_MAP[v_val]):
            raise ValueError(f"签名{idx} serialized_signature末尾字符与v值不匹配：v={v_val}应结尾为{HyperlaneConst.V_MAP[v_val]}")
    
    # 拼接前threshold个签名
    agg_sig_bytes = b""
    for sig in sigs[:threshold]:
        agg_sig_bytes += hex_to_bytes(sig["serialized_signature"], HyperlaneConst.SIGNATURE_BYTES_LENGTH)
    logger.info(f"签名处理完成：拼接{threshold}个合规签名，合集长度{len(agg_sig_bytes)}字节")
    logger.debug(f"签名合集十六进制：0x{agg_sig_bytes.hex()}")
    return agg_sig_bytes, base_hook_addr, base_message_id, base_mailbox_domain, base_checkpoint_root

# ======================== 【第五步：核心构造器类 - 无缩进/语法错误】 ========================
class HyperlaneMetadataBuilder(ABC):
    """Hyperlane Metadata抽象构造器（定义基础接口）"""
    def __init__(self, config: Dict):
        self.config = config
        self.agg_sig_bytes = None
        self.merkle_tree_hook_addr = None
        self.message_id = None
        self.mailbox_domain = None
        self.checkpoint_root = None
        self.merkle_tree_index_bytes = None
        self.merkle_hook_bytes = None
        self.message_id_bytes = None
        self.checkpoint_root_bytes = None
        self.checkpoint_index_bytes = None
        self._init_and_validate()

    def _init_and_validate(self):
        """初始化+全量参数校验（前置核心步骤）"""
        logger.info("初始化Metadata构造器，执行全量参数校验")
        # 1. 处理签名
        self.agg_sig_bytes, self.merkle_tree_hook_addr, self.message_id, self.mailbox_domain, self.checkpoint_root = process_and_validate_signatures(
            self.config["validator_signatures"], self.config["threshold"]
        )
        # 2. 转换核心字段为bytes
        self.merkle_tree_index_bytes = u32_to_big_endian_bytes(self.config["merkle_tree_index"])
        self.merkle_hook_bytes = hex_to_bytes(self.merkle_tree_hook_addr, HyperlaneConst.H256_BYTES_LENGTH)
        self.message_id_bytes = hex_to_bytes(self.message_id, HyperlaneConst.H256_BYTES_LENGTH)
        self.checkpoint_root_bytes = hex_to_bytes(self.checkpoint_root, HyperlaneConst.H256_BYTES_LENGTH)
        self.checkpoint_index_bytes = u32_to_big_endian_bytes(self.config["validator_signatures"][0]["value"]["checkpoint"]["index"])
        # 3. 校验构造类型
        if self.config["metadata_type"] not in [HyperlaneConst.METADATA_TYPE_MSG_ID, HyperlaneConst.METADATA_TYPE_MERKLE_ROOT]:
            raise ValueError(f"构造类型非法：合法值{HyperlaneConst.METADATA_TYPE_MSG_ID}/{HyperlaneConst.METADATA_TYPE_MERKLE_ROOT}")
        logger.info("构造器初始化完成，所有参数校验通过")

    @abstractmethod
    def build(self) -> Tuple[bytes, str]:
        """抽象构建方法（子类实现具体逻辑）"""
        pass

class MessageIdMultisigBuilder(HyperlaneMetadataBuilder):
    """MessageId类型构造器（轻量化，无Proof，推荐）"""
    def build(self) -> Tuple[bytes, str]:
        logger.info("构造【MessageIdMultisig】类型Metadata（轻量化，无Proof）")
        # 固定拼接顺序（源码硬编码）：32 hook +32 root +4 checkpoint_idx + N*65 sigs
        metadata_bytes = (
            self.merkle_hook_bytes
            + self.checkpoint_root_bytes
            + self.checkpoint_index_bytes
            + self.agg_sig_bytes
        )
        # 格式化输出
        metadata_hex = "0x" + metadata_bytes.hex()
        logger.info(f"MessageIdMultisig构造成功！总长度{len(metadata_bytes)}字节")
        logger.info(f"原生bytes：{metadata_bytes}")
        logger.info(f"十六进制（可直接提交交易）：{metadata_hex}")
        return metadata_bytes, metadata_hex

class MerkleRootMultisigBuilder(HyperlaneMetadataBuilder):
    """MerkleRoot类型构造器（完整版，带1024字节Proof）"""
    def build(self) -> Tuple[bytes, str]:
        logger.info("构造【MerkleRootMultisig】类型Metadata（完整版，带Proof）")
        # 1. 创建Web3客户端+计算Proof
        w3 = create_web3_client(self.config["rpc_nodes"])
        merkle_proof_bytes = calculate_merkle_proof(
            w3=w3,
            hook_addr=self.merkle_tree_hook_addr,
            leaf_index=self.config["merkle_tree_index"],
            message_id=self.message_id
        )
        # 固定拼接顺序（源码硬编码）：32 hook +4 leaf_idx +32 msg_id +1024 proof +4 checkpoint_idx + N*65 sigs
        metadata_bytes = (
            self.merkle_hook_bytes
            + self.merkle_tree_index_bytes
            + self.message_id_bytes
            + merkle_proof_bytes
            + self.checkpoint_index_bytes
            + self.agg_sig_bytes
        )
        # 格式化输出
        metadata_hex = "0x" + metadata_bytes.hex()
        logger.info(f"MerkleRootMultisig构造成功！总长度{len(metadata_bytes)}字节")
        return metadata_bytes, metadata_hex

# ======================== 【第六步：工厂类 - 统一入口】 ========================
class MetadataBuilderFactory:
    """构造器工厂类（解耦类型与逻辑）"""
    @staticmethod
    def create_builder(config: Dict) -> HyperlaneMetadataBuilder:
        """创建对应类型的构造器"""
        metadata_type = config["metadata_type"]
        if metadata_type == HyperlaneConst.METADATA_TYPE_MSG_ID:
            return MessageIdMultisigBuilder(config)
        elif metadata_type == HyperlaneConst.METADATA_TYPE_MERKLE_ROOT:
            return MerkleRootMultisigBuilder(config)
        else:
            raise ValueError(f"不支持的构造类型：{metadata_type}")

# ======================== 【第七步：主函数入口 - 一键运行】 ========================
def main() -> int:
    """主函数（脚本入口）"""
    logger.info("=" * 80)
    logger.info("Hyperlane Metadata构造脚本（最终修复版）开始运行")
    logger.info("=" * 80)
    try:
        # 创建构造器+构建Metadata
        builder = MetadataBuilderFactory.create_builder(INPUT_CONFIG)
        metadata_bytes, metadata_hex = builder.build()
        logger.info("=" * 80)
        logger.info("✅ Metadata构造完成！最终结果：")
        logger.info(f"✅ 构造类型：{INPUT_CONFIG['metadata_type'].upper()}")
        logger.info(f"✅ 原生bytes：{metadata_bytes}")
        logger.info(f"✅ 十六进制格式（推荐提交交易）：{metadata_hex}")
        logger.info("=" * 80)
        return 0
    except Exception as e:
        logger.error(f"❌ 构造失败！错误原因：{str(e)}", exc_info=True)
        logger.info("=" * 80)
        return 1

if __name__ == "__main__":
    sys.exit(main())