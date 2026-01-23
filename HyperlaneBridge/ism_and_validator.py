import json
import time
import logging
from typing import List, Dict, Any, Optional

from web3 import Web3
from web3.exceptions import ContractLogicError

# 该脚本用于递归查找最终执行验证的ISM合约的地址、module type、阈值、验证者列表及其存储位置。输出为JSON文件。
'''ModuleType类型介绍 {
  UNUSED, // 0 未使用/占位值：初始化、预留位，无任何业务逻辑，仅做数字填充
  ROUTING, // 1 路由型ISM：核心类型，负责「跨链消息的路由分发」，将消息转发到对应的子安全模块做验证，类似网关路由
  AGGREGATION, // 2 聚合型ISM：核心类型，需要「多个子安全模块同时验证通过」才放行消息，是多签的进阶版，多重安全校验
  LEGACY_MULTISIG, // 3 旧版多签ISM：【DEPRECATED=已废弃】历史遗留的多签验证方式，项目中禁止使用，仅做兼容历史版本
  MERKLE_ROOT_MULTISIG, // 4 默克尔根多签ISM：基于「默克尔根+多签」的验证方式，适合批量跨链消息的高效验证，性能极佳
  MESSAGE_ID_MULTISIG, // 5 消息ID多签ISM：基于「单条消息唯一ID+多签」的验证方式，适合单条重要消息的精准验证，安全性拉满
  NULL, // 6 空安全模块：【无任何验证逻辑】跨链消息无需验证直接通过！仅用于「测试环境/内部信任链」，生产环境绝对禁用，风险极高
  CCIP_READ, // 7 CCIP读取型ISM：基于以太坊CCIP Read协议，支持「链下数据+链上验证」的跨链安全规则，链下链上协同验证
  ARB_L2_TO_L1, // 8 Arbitrum专属型：专门适配「Arbitrum L2 → Ethereum L1」的跨链场景，匹配Arbitrum的跨链消息规则
  WEIGHTED_MERKLE_ROOT_MULTISIG, //9 带权重的默克尔根多签：多签节点不是平权的，不同节点有不同权重，累计权重达标即通过，适合联盟链/机构协作
  WEIGHTED_MESSAGE_ID_MULTISIG, //10 带权重的消息ID多签：结合「单条消息精准验证」+「权重多签」，兼顾精准度和灵活性，高级验证方式
}'''

# ============================================================
# 配置区（你可以改这里）
# ============================================================

RPC_ENDPOINTS = [
    "https://rpc-bsc.48.club",
    "https://binance.llamarpc.com"
    #"https://base.drpc.org",
    #"https://mainnet.base.org",
    #"https://base-mainnet.public.blastapi.io"
    # 备用 RPC
]

APP_CONTRACT_ADDRESS = "0x6f0037C79d144d5B8E3E6f04E49FBb5f25fD508f" # 项目方自己部署的跨链桥合约地址
MAILBOX_ADDRESS = "0x2971b9Aec44bE4eb673DF1B88cDB57b96eefe8a4"   # hyperlane 官方部署的 mailbox address
VALIDATOR_ANNOUNCE_ADDRESS = "0x7024078130D9c2100fEA474DAD009C2d1703aCcd"  # hyperlane 官方部署的 ValidatorAnnounce address

MESSAGE_BYTES = bytes.fromhex(
    "03002464ca0000a4b10000000000000000000000006720350f7e3323418c05645cd5d6bb055f4a7427000000380000000000000000000000006f0037c79d144d5b8e3e6f04e49fbb5f25fd508f000000000000000000000000cc7150deedc2cea70d44033c5c31ea3466a9dd0d00000000000000000000000000000000000000000000bd50d3d9e5413bf3e800"
)  # message，无需0x前缀，找一笔已经跨链成功的交易，把目标链的输入参数的message放这里即可

LOG_FILE = "ism_trace.log" #输出日志文件名
OUTPUT_JSON = "ism_result_rcade.json"  # 输出结果 JSON 文件名

# ============================================================
# ABI 定义（严格使用你给的）
# ============================================================

APP_ABI = [
    {
        "inputs": [],
        "name": "interchainSecurityModule",
        "outputs": [{"internalType": "contract IInterchainSecurityModule", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]

MAILBOX_ABI = [
    {
        "inputs": [],
        "name": "defaultIsm",
        "outputs": [{"internalType": "contract IInterchainSecurityModule", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]

ISM_ABI = [
    {
        "inputs": [],
        "name": "moduleType",
        "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes", "name": "_message", "type": "bytes"}],
        "name": "route",
        "outputs": [{"internalType": "contract IInterchainSecurityModule", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes", "name": "", "type": "bytes"}],
        "name": "modulesAndThreshold",
        "outputs": [
            {"internalType": "address[]", "name": "", "type": "address[]"},
            {"internalType": "uint8", "name": "", "type": "uint8"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes", "name": "", "type": "bytes"}],
        "name": "validatorsAndThreshold",
        "outputs": [
            {"internalType": "address[]", "name": "", "type": "address[]"},
            {"internalType": "uint8", "name": "", "type": "uint8"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
]

VALIDATOR_ANNOUNCE_ABI = [
    {
        "inputs": [{"internalType": "address[]", "name": "_validators", "type": "address[]"}],
        "name": "getAnnouncedStorageLocations",
        "outputs": [{"internalType": "string[][]", "name": "", "type": "string[][]"}],
        "stateMutability": "view",
        "type": "function",
    }
]

# ============================================================
# ModuleType 常量（只支持你确认的）
# ============================================================

MODULE_TYPE_ROUTING = 1
MODULE_TYPE_AGGREGATION = 2
MODULE_TYPE_MERKLE_MULTISIG = 4
MODULE_TYPE_MESSAGE_ID_MULTISIG = 5
MODULE_TYPE_CCIP_READ = 7

# ============================================================
# Logging 初始化
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)

logger = logging.getLogger(__name__)

# ============================================================
# Web3 + RPC 管理
# ============================================================

class Web3Manager:
    def __init__(self, rpc_endpoints: List[str]):
        self.rpc_endpoints = rpc_endpoints
        self.web3_objects = [Web3(Web3.HTTPProvider(rpc)) for rpc in rpc_endpoints]

    def call_contract(self, contract, fn_name: str, args: list):
        last_error = None
        for w3 in self.web3_objects:
            try:
                fn = getattr(contract.functions, fn_name)(*args)
                return fn.call()
            except Exception as e:
                logger.error(f"RPC call failed on {w3.provider.endpoint_uri}: {e}")
                last_error = e
                time.sleep(0.2)
        raise last_error

# ============================================================
# ISM 解析核心逻辑
# ============================================================

class ISMResolver:
    def __init__(self, w3_manager: Web3Manager):
        self.w3m = w3_manager

    def resolve_ism(self, ism_address: str, message: bytes) -> Dict[str, Any]:
        logger.info(f"Resolving ISM: {ism_address}")

        ism_contract = self.w3m.web3_objects[0].eth.contract(
            address=Web3.to_checksum_address(ism_address),
            abi=ISM_ABI,
        )

        module_type = self.w3m.call_contract(ism_contract, "moduleType", [])
        logger.info(f"ISM {ism_address} moduleType = {module_type}")

        node: Dict[str, Any] = {
            "ism": ism_address,
            "moduleType": module_type,
        }

        # Routing ISM
        if module_type == MODULE_TYPE_ROUTING:
            next_ism = self.w3m.call_contract(ism_contract, "route", [message])
            node["type"] = "Routing"
            node["children"] = [self.resolve_ism(next_ism, message)]
            return node

        # Aggregation ISM
        if module_type == MODULE_TYPE_AGGREGATION:
            modules, threshold = self.w3m.call_contract(
                ism_contract, "modulesAndThreshold", [message]
            )
            node["type"] = "Aggregation"
            node["threshold"] = threshold
            node["children"] = [self.resolve_ism(m, message) for m in modules]
            return node

        # Multisig ISM
        if module_type in (MODULE_TYPE_MERKLE_MULTISIG, MODULE_TYPE_MESSAGE_ID_MULTISIG):
            validators, threshold = self.w3m.call_contract(
                ism_contract, "validatorsAndThreshold", [message]
            )

            va_contract = self.w3m.web3_objects[0].eth.contract(
                address=Web3.to_checksum_address(VALIDATOR_ANNOUNCE_ADDRESS),
                abi=VALIDATOR_ANNOUNCE_ABI,
            )

            locations = self.w3m.call_contract(
                va_contract, "getAnnouncedStorageLocations", [validators]
            )

            node["type"] = "Multisig"
            node["multisigType"] = (
                "MerkleRoot" if module_type == MODULE_TYPE_MERKLE_MULTISIG else "MessageId"
            )
            node["threshold"] = threshold
            node["validators"] = [
                {"address": v, "storage": locations[i]}
                for i, v in enumerate(validators)
            ]
            return node

        # Offchain Lookup
        if module_type == MODULE_TYPE_CCIP_READ:
            node["type"] = "OffchainLookup"
            return node

        # Unsupported
        logger.warning(f"Unsupported moduleType {module_type} at ISM {ism_address}")
        node["type"] = "Unsupported"
        return node

# ============================================================
# 主流程
# ============================================================

def main():
    w3m = Web3Manager(RPC_ENDPOINTS)

    app_contract = w3m.web3_objects[0].eth.contract(
        address=Web3.to_checksum_address(APP_CONTRACT_ADDRESS),
        abi=APP_ABI,
    )

    root_ism = w3m.call_contract(app_contract, "interchainSecurityModule", [])

    if root_ism == "0x0000000000000000000000000000000000000000":
        logger.info("App returned zero ISM, fallback to Mailbox defaultIsm")
        mailbox = w3m.web3_objects[0].eth.contract(
            address=Web3.to_checksum_address(MAILBOX_ADDRESS),
            abi=MAILBOX_ABI,
        )
        root_ism = w3m.call_contract(mailbox, "defaultIsm", [])

    logger.info(f"Root ISM resolved: {root_ism}")

    resolver = ISMResolver(w3m)
    result_tree = resolver.resolve_ism(root_ism, MESSAGE_BYTES)

    output = {
        "root_ism": root_ism,
        "message": MESSAGE_BYTES.hex(),
        "result": result_tree,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    logger.info(f"Result written to {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
