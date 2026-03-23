from web3 import Web3
from eth_abi import encode
from decimal import Decimal

w3 = Web3()


"""该脚本构建的v2流动性池的多跳路径输入参数，可以用于调用Universal Router的execute多跳功能。
成功交易：https://dashboard.tenderly.co/xiaobei/project/simulator/bc27e620-9ae2-451b-b558-c23f882a381a"""



# =========================
# 你需要填写的参数
# =========================

# token 地址（必须 checksum）
token0 = Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955") #usdt
token1 = Web3.to_checksum_address("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c") #wbnb
token2 = Web3.to_checksum_address("0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82") #cake

# 链上池子：
# v2 usdt/wbnb 池子：https://pancakeswap.finance/liquidity/pool/bsc/0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE
# v2 wbnb/cake 池子：https://pancakeswap.finance/liquidity/pool/bsc/0x0eD7e52944161450477ee417DE9Cd3a859b14fD0

# swap 参数（例如 0.1 token）
amount_in = int(Decimal("0.1") * 10**18)
amount_out_min = 0

# payer 是否是用户
payer_is_user = True

# =========================
# 1️⃣ 构造多跳 path（V2 核心）
# =========================
# token0 → token1 → token2
path = [token0, token1, token2]

# =========================
# 2️⃣ MSG_SENDER（关键）
# =========================
MSG_SENDER = Web3.to_checksum_address("0x0000000000000000000000000000000000000001")

# =========================
# 3️⃣ 构造 inputs[0]
# =========================
input0 = encode(
    ['address', 'uint256', 'uint256', 'address[]', 'bool'],
    [
        MSG_SENDER,       # recipient（= msg.sender）
        amount_in,        # amountIn
        amount_out_min,   # amountOutMin
        path,             # 多跳路径
        payer_is_user
    ]
)

# =========================
# 4️⃣ 输出 hex（直接粘浏览器）
# =========================
print("input0 (hex):", "0x" + input0.hex())