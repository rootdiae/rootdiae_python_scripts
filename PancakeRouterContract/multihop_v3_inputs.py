from web3 import Web3
from eth_abi import encode
from eth_abi.packed import encode_packed
from decimal import Decimal

w3 = Web3()

"""该脚本构建的v3流动性池的多跳路径输入参数，可以用于调用Universal Router的execute多跳功能。
成功交易：https://dashboard.tenderly.co/xiaobei/project/simulator/7ca49b39-2e3a-4c8b-8605-2e9b10c6c36f/debugger?trace=0"""


# =========================
# 你需要填写的参数
# =========================

# token 地址（必须是 checksum 地址）
token0 = Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955") #usdt
token1 = Web3.to_checksum_address("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c") #wbnb
token2 = Web3.to_checksum_address("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d") #usdc

# fee（uint24）
fee1 = 100   # 例如 0.25%,  pool token0/token1 的费率，v3 usdt/wbnb 0.01%,https://pancakeswap.finance/liquidity/pool/bsc/0x172fcD41E0913e95784454622d1c3724f546f849
fee2 = 100   #pool token1/token2 的费率，v3 wbnb/usdc 0.01%,https://pancakeswap.finance/liquidity/pool/bsc/0xf2688Fb5B81049DFB7703aDa5e770543770612C4

# swap 参数
amount_in = int(Decimal("0.1") * 10**18)
amount_out_min = 0          # 测试一般填 0

# payer 是否是用户
payer_is_user = True

MSG_SENDER = Web3.to_checksum_address("0x0000000000000000000000000000000000000001")

# =========================
# ✅ 正确方式：encodePacked 构造 path
# =========================
def encode_path(token0, fee1, token1, fee2, token2):
    return encode_packed(
        ['address', 'uint24', 'address', 'uint24', 'address'],
        [token0, fee1, token1, fee2, token2]
    )

path = encode_path(token0, fee1, token1, fee2, token2)

# =========================
# ✅ 标准 ABI encode inputs
# =========================
input0 = encode(
    ['address', 'uint256', 'uint256', 'bytes', 'bool'],
    [
        MSG_SENDER,
        amount_in,
        amount_out_min,
        path,
        payer_is_user
    ]
)

# =========================
# 输出 hex（可直接粘）
# =========================
print("input0 (hex):", input0.hex())