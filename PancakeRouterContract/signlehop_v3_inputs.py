from web3 import Web3
from eth_abi import encode
from eth_abi.packed import encode_packed
from decimal import Decimal

w3 = Web3()

# =========================
# 参数（你可以替换）
# =========================

tokenin = Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955")  # USDT
tokenout = Web3.to_checksum_address("0x000Ae314E2A2172a039B26378814C252734f556A")  # WBNB

fee = 500  

amount_in = int(Decimal("0.1") * 10**18)
amount_out_min = 0

payer_is_user = True

# Universal Router sentinel
MSG_SENDER = Web3.to_checksum_address("0x0000000000000000000000000000000000000001")

# =========================
# 1️⃣ 构造 V3 path（单跳）
# =========================
def encode_path(token0, fee, token1):
    return encode_packed(
        ['address', 'uint24', 'address'],
        [token0, fee, token1]
    )

path = encode_path(tokenin, fee, tokenout)

# =========================
# 2️⃣ ABI encode inputs
# =========================
input0 = encode(
    ['address', 'uint256', 'uint256', 'bytes', 'bool'],
    [
        MSG_SENDER,     # recipient
        amount_in,
        amount_out_min,
        path,
        payer_is_user
    ]
)

# =========================
# 输出
# =========================
print("input0 (hex):", input0.hex())