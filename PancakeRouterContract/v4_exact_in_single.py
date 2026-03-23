#!/usr/bin/env python3
"""
Python implementation to construct input data for test_infiClSwap_ExactInSingle()
"""


"""该脚本构建的v4 cl流动性池的单跳路径输入参数，可以用于调用Universal Router的execute单跳功能。
对应测试函数：CLPancakeSwapInfinity.t.sol 的 test_infiClSwap_ExactInSingle
必须严格按照池子的currency0和currency1的顺序输入.
zero_for_one=True 表示输入的token是currency0，输出的token是currency1。
zero_for_one=False 表示输入的token是currency1，输出的token是currency0。
非bnb池子和bnb池子的编码方式相同"""


from eth_abi import encode
from web3 import Web3
from decimal import Decimal

# Constants
CL_SWAP_EXACT_IN_SINGLE = 0x06
SETTLE_ALL = 0x0c
TAKE_ALL = 0x0f
INFI_SWAP = 0x10
MSG_SENDER = "0x0000000000000000000000000000000000000001"   # ActionConstants.MSG_SENDER


# Structs
class PoolKey:
    """PoolKey struct"""
    def __init__(self, currency0, currency1, hooks, pool_manager, fee, parameters):
        self.currency0 = currency0
        self.currency1 = currency1
        self.hooks = hooks
        self.pool_manager = pool_manager
        self.fee = fee
        self.parameters = parameters
    
class CLSwapExactInputSingleParams:
    """CLSwapExactInputSingleParams struct"""
    def __init__(self, pool_key, zero_for_one, amount_in, amount_out_min, hook_data):
        self.pool_key = pool_key
        self.zero_for_one = zero_for_one
        self.amount_in = amount_in
        self.amount_out_min = amount_out_min
        self.hook_data = hook_data
    


    def encode(self):
        # 确保 parameters 是 bytes 类型
        if isinstance(self.pool_key.parameters, str):
            parameters_bytes = bytes.fromhex(self.pool_key.parameters.replace('0x', ''))
        else:
            parameters_bytes = self.pool_key.parameters
        
        # 构建参数值
        values = [
            (
                (
                    self.pool_key.currency0,
                    self.pool_key.currency1,
                    self.pool_key.hooks,
                    self.pool_key.pool_manager,
                    self.pool_key.fee,
                    parameters_bytes
                ),
                self.zero_for_one,
                self.amount_in,
                self.amount_out_min,
                self.hook_data
            )
        ]
        
        # 定义对应的类型
        types = [
            '((address,address,address,address,uint24,bytes32),bool,uint128,uint128,bytes)'
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

def construct_infi_cl_swap_exact_in_single_input(
    token0_address, 
    token1_address, 
    pool_manager_address, 
    fee, 
    amount_in
):
    """
    Construct input data for test_infiClSwap_ExactInSingle()
    
    Args:
        token0_address: Address of token0
        token1_address: Address of token1
        pool_manager_address: Address of CLPoolManager
        fee: Fee tier (e.g., 3000 for 0.3%)
        amount_in: Amount of token0 to swap
    
    Returns:
        commands: Encoded commands
        inputs: Encoded inputs
    """
    # Create PoolKey
    pool_key = PoolKey(
        currency0=token0_address,
        currency1=token1_address,
        hooks=Web3.to_checksum_address('0x9a9B5331ce8d74b2B721291D57DE696E878353fd'),  # No hooks
        pool_manager=pool_manager_address,
        fee=fee,
        parameters='0x00000000000000000000000000000000000000000000000000000000000a0055'  # tickSpacing=10
    )
    
    # Create CLSwapExactInputSingleParams
    params = CLSwapExactInputSingleParams(
        pool_key=pool_key,
        zero_for_one=True,  # token0 to token1
        amount_in=amount_in,
        amount_out_min=0,
        hook_data=b''
    )
    
    # Create plan
    plan = Plan()
    plan.add(CL_SWAP_EXACT_IN_SINGLE, params.encode())
    
    # Finalize swap
    data = plan.finalize_swap(token0_address, token1_address, MSG_SENDER)
    
    # Create commands
    commands = bytes([INFI_SWAP])
    
    # Create inputs
    inputs = [data]
    
    return commands, inputs

# Example usage
if __name__ == "__main__":
    # Test parameters (replace with actual addresses)
    token0 = Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955")
    token1 = Web3.to_checksum_address("0x7ec43Cf65F1663F820427C62A5780b8f2E25593A")
    pool_manager = Web3.to_checksum_address("0xa0FfB9c1CE1Fe56963B0321B32E7A0302114058b")
    fee = 67  
    amount_in = int(Decimal("0.1") * 10**18)
    
    commands, inputs = construct_infi_cl_swap_exact_in_single_input(
        token0, token1, pool_manager, fee, amount_in
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