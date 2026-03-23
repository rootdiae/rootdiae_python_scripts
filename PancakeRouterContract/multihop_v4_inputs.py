#!/usr/bin/env python3
"""
Python implementation to construct input data for test_infiClSwap_ExactIn_MultiHop()
"""

"""该脚本构建的v4流动性池的多个池子多跳路径输入参数，可以用于调用Universal Router的execute多跳功能。
对应测试函数：CLPancakeSwapInfinity.t.sol 的 test_infiClSwap_ExactIn_MultiHop
没有方向定义，amount_in 表示输入的token,是currency0还是currency1都可以，path_key.intermediate_currency 表示输出的token，也就是该池子的另外一个currency.
非bnb池子和bnb池子的编码方式相同"""


from eth_abi import encode
from web3 import Web3
from decimal import Decimal

# Constants
CL_SWAP_EXACT_IN = 0x07
SETTLE_ALL = 0x0c
TAKE_ALL = 0x0f
INFI_SWAP = 0x10
MSG_SENDER = "0x0000000000000000000000000000000000000001"   # ActionConstants.MSG_SENDER

# Structs
class PathKey:
    """PathKey struct"""
    def __init__(self, intermediate_currency, fee, hooks, hook_data, pool_manager, parameters):
        self.intermediate_currency = intermediate_currency
        self.fee = fee
        self.hooks = hooks
        self.hook_data = hook_data
        self.pool_manager = pool_manager
        self.parameters = parameters
    

class CLSwapExactInputParams:
    """CLSwapExactInputParams struct"""
    def __init__(self, currency_in, path, amount_in, amount_out_min):
        self.currency_in = currency_in
        self.path = path
        self.amount_in = amount_in
        self.amount_out_min = amount_out_min
    
    def encode(self):
        """Encode CLSwapExactInputParams struct as a single top-level nested tuple"""
        # 编码 PathKey 数组
        encoded_path = []
        for path_key in self.path:
            # 确保 parameters 是 bytes 类型
            if isinstance(path_key.parameters, str):
                parameters_bytes = bytes.fromhex(path_key.parameters.replace('0x', ''))
            else:
                parameters_bytes = path_key.parameters
            
            # 确保 hook_data 是 bytes 类型
            if isinstance(path_key.hook_data, str):
                hook_data_bytes = bytes.fromhex(path_key.hook_data.replace('0x', ''))
            else:
                hook_data_bytes = path_key.hook_data
            
            encoded_path.append((
                path_key.intermediate_currency,
                path_key.fee,
                path_key.hooks,
                path_key.pool_manager,                
                hook_data_bytes,
                parameters_bytes
            ))
        
        # 构建单个顶级嵌套元组
        values = [
            (
                self.currency_in,
                encoded_path,
                self.amount_in,
                self.amount_out_min
            )
        ]
        
        # 定义对应的类型
        types = [
            '(address,(address,uint24,address,address,bytes,bytes32)[],uint128,uint128)'
        ]
        
        return encode(types, values)

class Plan:
    """Plan class to mimic Solidity Planner library"""
    def __init__(self):
        self.actions = b''
        self.params = []
    
    def add(self, action, param):
        """Add an action to the plan"""
        self.actions += bytes([action & 0xff])  # Take only the first byte
        self.params.append(param)
        return self
    
    def encode(self):
        return encode(
            ["bytes", "bytes[]"],
            [self.actions, self.params]
        )
    
    def finalize_swap(self, input_currency, output_currency, take_recipient):
        """Finalize swap by adding settle and take actions"""
        
        if take_recipient == MSG_SENDER:
            # ✅ 标准 ABI：一次 encode 多个参数
            settle_all_param = encode(
                ["address", "uint256"],
                [input_currency, 2**256 - 1]
            )
            self.add(SETTLE_ALL, settle_all_param)

            take_all_param = encode(
                ["address", "uint256"],
                [output_currency, 0]
            )
            self.add(TAKE_ALL, take_all_param)

        else:
            # 👉 建议你别 silent pass，容易踩坑
            raise NotImplementedError("Only MSG_SENDER path supported")

        return self.encode()

def construct_infi_cl_swap_exact_in_multi_hop_input(
    token0_address, 
    token1_address, 
    token2_address, 
    amount_in
):
    """
    Construct input data for test_infiClSwap_ExactIn_MultiHop()
    
    Args:
        token0_address: Address of token0
        token1_address: Address of token1
        token2_address: Address of token2
        pool_manager_address: Address of CLPoolManager
        amount_in: Amount of token0 to swap
    
    Returns:
        commands: Encoded commands
        inputs: Encoded inputs
    """
    # Create PathKey array (multi-hop: token0 → token1 → token2)
    path = [
        PathKey(
            intermediate_currency=token1_address,
            fee=1,
            hooks=Web3.to_checksum_address('0x0000000000000000000000000000000000000000'),  # No hooks
            pool_manager=Web3.to_checksum_address('0xa0FfB9c1CE1Fe56963B0321B32E7A0302114058b'),
            hook_data=b'',            
            parameters='0x0000000000000000000000000000000000000000000000000000000000010000'  # tickSpacing=10
        ),
        PathKey(
            intermediate_currency=token2_address,
            fee=67,
            hooks=Web3.to_checksum_address('0x72e09eBd9b24F47730b651889a4eD984CBa53d90'),  # No hooks
            pool_manager=Web3.to_checksum_address('0xa0FfB9c1CE1Fe56963B0321B32E7A0302114058b'),
            hook_data=b'',            
            parameters='0x00000000000000000000000000000000000000000000000000000000000a0055'  # tickSpacing=10
        )
    ]
    
    # Create CLSwapExactInputParams
    params = CLSwapExactInputParams(
        currency_in=token0_address,
        path=path,
        amount_in=amount_in,
        amount_out_min=0
    )
    
    # Create plan
    plan = Plan()
    plan.add(CL_SWAP_EXACT_IN, params.encode())
    
    # Finalize swap
    data = plan.finalize_swap(token0_address, token2_address, MSG_SENDER)
    
    # Create commands
    commands = bytes([INFI_SWAP])
    
    # Create inputs
    inputs = [data]
    
    return commands, inputs

# Example usage
if __name__ == "__main__":
    # Test parameters (replace with actual addresses)
    token0 = Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955")  # USDT
    token1 = Web3.to_checksum_address("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d") # USDC
    token2 = Web3.to_checksum_address("0x0C69199C1562233640e0Db5Ce2c399A88eB507C7")  # cys
    amount_in = int(Decimal("0.01") * 10**18)
    
    # Construct input data
    commands, inputs = construct_infi_cl_swap_exact_in_multi_hop_input(
        token0, token1, token2, amount_in
    )
    
    # Print results
    print("Commands:")
    print(f"Hex: 0x{commands.hex()}")
    print(f"Length: {len(commands)} bytes")
    print()
    print("Inputs:")
    for i, input_data in enumerate(inputs):
        print(f"Input {i}:")
        print(f"Hex: 0x{input_data.hex()}")
        print(f"Length: {len(input_data)} bytes")
        print()
    
    print("\nTo use these in a transaction:")
    print(f"- Call execute() with commands: 0x{commands.hex()}")
    print(f"- And inputs array containing the input data")