from web3 import Web3
from eth_abi import encode
from decimal import Decimal

w3 = Web3()

"""该脚本构建的v2流动性池的单跳路径输入参数，可以用于调用Universal Router的execute单跳功能。
成功交易：https://dashboard.tenderly.co/xiaobei/project/simulator/43e86c2d-5250-4722-bddf-17b257c1b1a8
"""

# =========================
# 你需要填写的参数
# =========================

# token 地址（必须 checksum）
token0 = Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955") #usdt
token1 = Web3.to_checksum_address("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c") #wbnb

#链上v2 usdt/wbnb 池子：https://pancakeswap.finance/liquidity/pool/bsc/0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE

# swap 参数
amount_in = int(Decimal("0.1") * 10**18)
amount_out_min = 0        # 测试一般填 0

# payer 是否是用户
payer_is_user = True

# =========================
# 1️⃣ 构造 path（V2是 address[]）
# =========================
path = [token0, token1]

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
        MSG_SENDER,     # recipient
        amount_in,      # amountIn
        amount_out_min, # amountOutMin
        path,           # address[]
        payer_is_user
    ]
)

# =========================
# 4️⃣ 输出 hex（直接粘浏览器）
# =========================
print("input0 (hex):", "0x" + input0.hex())