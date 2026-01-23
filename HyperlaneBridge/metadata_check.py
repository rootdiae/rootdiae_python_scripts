import re
from typing import Dict, Tuple, Optional

# Hyperlane Metadata解析器 - 分析metadata类型（messageid和merkleroot)、阈值和潜在问题。
# 输入：metadata十六进制字符串
# 输出：类型判断、阈值计算、字节分析和问题检测

# Hyperlane官方常量
HYPERLANE_CONST = {
    "TREE_DEPTH": 32,
    "PROOF_BYTES_LENGTH": 32 * 32,  # 1024字节
    "U32_BYTE_LENGTH": 4,
    "H256_BYTES_LENGTH": 32,
    "ETH_ADDR_BYTES_LENGTH": 20,
    "SIGNATURE_BYTES_LENGTH": 65,
    "VALID_V_VALUES": [27, 28],
    "V_MAP": {27: "1b", 28: "1c"},
}

def hex_to_bytes(hex_str: str) -> bytes:
    """安全的十六进制字符串转bytes"""
    if not hex_str.startswith("0x"):
        raise ValueError("十六进制字符串必须以0x开头")
    return bytes.fromhex(hex_str[2:])

def analyze_metadata(metadata_hex: str) -> Dict:
    """
    分析Hyperlane metadata，判断类型和阈值
    """
    # 1. 转换为bytes并计算总长度
    metadata_bytes = hex_to_bytes(metadata_hex)
    total_bytes = len(metadata_bytes)
    print(f"✅ Metadata总字节数: {total_bytes}")
    print(f"✅ Metadata十六进制长度: {len(metadata_hex)} 字符")
    
    # 2. 尝试识别类型
    # MerkleRootMultisig固定部分长度: 32(hook) + 4(leaf_idx) + 32(msg_id) + 1024(proof) + 4(checkpoint_idx) = 1096
    # MessageIdMultisig固定部分长度: 32(hook) + 32(root) + 4(checkpoint_idx) = 68
    
    merkle_root_fixed = 32 + 4 + 32 + 1024 + 4  # 1096字节
    message_id_fixed = 32 + 32 + 4  # 68字节
    
    # 计算剩余签名部分的字节数
    remaining_merkle = total_bytes - merkle_root_fixed
    remaining_message_id = total_bytes - message_id_fixed
    
    # 检查哪种类型的剩余部分能被65整除（签名长度）
    is_merkle_root = (remaining_merkle >= 0 and remaining_merkle % 65 == 0)
    is_message_id = (remaining_message_id >= 0 and remaining_message_id % 65 == 0)
    
    result = {
        "total_bytes": total_bytes,
        "metadata_hex_prefix": metadata_hex[:100] + "..." if len(metadata_hex) > 100 else metadata_hex,
        "bytes_hex_prefix": metadata_bytes.hex()[:100] + "..." if len(metadata_bytes.hex()) > 100 else metadata_bytes.hex(),
    }
    
    # 3. 判断类型和计算阈值
    if is_merkle_root and not is_message_id:
        result["type"] = "MerkleRootMultisig"
        result["threshold"] = remaining_merkle // 65
        result["fixed_part_bytes"] = merkle_root_fixed
        result["signatures_bytes"] = remaining_merkle
        # 提取各个字段
        try:
            # MerkleRootMultisig结构: [32-hook][4-leaf_idx][32-msg_id][1024-proof][4-checkpoint_idx][N*65-sigs]
            offset = 0
            hook_addr = metadata_bytes[offset:offset+32].hex()
            offset += 32
            leaf_index = int.from_bytes(metadata_bytes[offset:offset+4], 'big')
            offset += 4
            message_id = metadata_bytes[offset:offset+32].hex()
            offset += 32
            proof = metadata_bytes[offset:offset+1024]
            offset += 1024
            checkpoint_idx = int.from_bytes(metadata_bytes[offset:offset+4], 'big')
            offset += 4
            
            result["parsed_fields"] = {
                "hook_address": f"0x{hook_addr}",
                "hook_address_20bytes": f"0x{hook_addr[-40:]}",  # 后20字节为实际地址
                "leaf_index": leaf_index,
                "message_id": f"0x{message_id}",
                "proof_length": len(proof),
                "proof_is_zero": all(b == 0 for b in proof),  # 检查proof是否全为零
                "checkpoint_index": checkpoint_idx,
                "signatures_start_offset": offset,
            }
        except Exception as e:
            result["parse_error"] = str(e)
            
    elif is_message_id and not is_merkle_root:
        result["type"] = "MessageIdMultisig"
        result["threshold"] = remaining_message_id // 65
        result["fixed_part_bytes"] = message_id_fixed
        result["signatures_bytes"] = remaining_message_id
        # 提取各个字段
        try:
            # MessageIdMultisig结构: [32-hook][32-root][4-checkpoint_idx][N*65-sigs]
            offset = 0
            hook_addr = metadata_bytes[offset:offset+32].hex()
            offset += 32
            checkpoint_root = metadata_bytes[offset:offset+32].hex()
            offset += 32
            checkpoint_idx = int.from_bytes(metadata_bytes[offset:offset+4], 'big')
            offset += 4
            
            result["parsed_fields"] = {
                "hook_address": f"0x{hook_addr}",
                "hook_address_20bytes": f"0x{hook_addr[-40:]}",
                "checkpoint_root": f"0x{checkpoint_root}",
                "checkpoint_index": checkpoint_idx,
                "signatures_start_offset": offset,
            }
        except Exception as e:
            result["parse_error"] = str(e)
    else:
        # 两种都匹配或都不匹配
        if is_merkle_root and is_message_id:
            result["type"] = "AMBIGUOUS"
            result["possible_types"] = {
                "MerkleRootMultisig": {"threshold": remaining_merkle // 65},
                "MessageIdMultisig": {"threshold": remaining_message_id // 65},
            }
            result["warning"] = "无法确定类型，请提供更多上下文或检查metadata格式"
        else:
            result["type"] = "UNKNOWN"
            result["error"] = "无法识别metadata类型，可能格式错误"
    
    # 4. 分析签名部分
    if "threshold" in result:
        signatures_start = result.get("parsed_fields", {}).get("signatures_start_offset", 
            result["fixed_part_bytes"] if "fixed_part_bytes" in result else None)
        
        if signatures_start:
            signatures = metadata_bytes[signatures_start:]
            result["signatures_info"] = {
                "total_signatures": result["threshold"],
                "signatures_bytes_length": len(signatures),
                "expected_signatures_bytes": result["threshold"] * 65,
                "signatures_match": len(signatures) == result["threshold"] * 65,
                "signatures_hex_prefix": signatures.hex()[:130] + "..." if len(signatures.hex()) > 130 else signatures.hex(),
            }
            
            # 检查每个签名的v值
            signature_issues = []
            for i in range(result["threshold"]):
                start = i * 65
                end = start + 65
                if end > len(signatures):
                    break
                sig = signatures[start:end]
                v_byte = sig[64]  # 第65个字节是v
                if v_byte not in HYPERLANE_CONST["VALID_V_VALUES"]:
                    signature_issues.append({
                        "signature_index": i,
                        "v_value": v_byte,
                        "expected_v": HYPERLANE_CONST["VALID_V_VALUES"],
                    })
            
            if signature_issues:
                result["signature_issues"] = signature_issues
    
    # 5. 检查潜在问题
    issues = []
    
    # 检查总长度是否合理
    if total_bytes < 68:  # MessageIdMultisig最小长度
        issues.append(f"总长度过短: {total_bytes}字节，至少需要68字节")
    elif total_bytes > 5000:  # 过大检查
        issues.append(f"总长度异常大: {total_bytes}字节，请确认数据正确")
    
    # 检查hook地址格式
    if "parsed_fields" in result:
        hook_hex = result["parsed_fields"]["hook_address"][2:]  # 去掉0x
        if len(hook_hex) != 64:  # 32字节=64十六进制字符
            issues.append(f"Hook地址长度异常: {len(hook_hex)//2}字节，应为32字节")
        # 检查是否前12字节全为0（标准格式）
        if hook_hex[:24] != "000000000000000000000000":
            issues.append(f"Hook地址前12字节不全为0: 0x{hook_hex[:24]}，可能格式错误")
    
    # 检查proof是否为全零（如果是MerkleRoot类型）
    if result.get("type") == "MerkleRootMultisig" and "parsed_fields" in result:
        if result["parsed_fields"].get("proof_is_zero"):
            issues.append("MerkleProof部分全为零，可能计算错误或占位符")
    
    if issues:
        result["issues"] = issues
    
    return result

def print_analysis(result: Dict):
    """打印分析结果"""
    print("\n" + "="*80)
    print("HYPERLANE METADATA 分析结果")
    print("="*80)
    
    print(f"📊 元数据类型: {result.get('type', '未知')}")
    
    if "threshold" in result:
        print(f"🔢 验证者阈值: {result['threshold']}")
    
    if "parsed_fields" in result:
        print(f"\n📋 解析字段:")
        for key, value in result["parsed_fields"].items():
            if isinstance(value, str) and len(value) > 66:
                print(f"  {key}: {value[:66]}...")
            else:
                print(f"  {key}: {value}")
    
    if "signatures_info" in result:
        print(f"\n🖊️  签名信息:")
        sig_info = result["signatures_info"]
        print(f"  签名总数: {sig_info['total_signatures']}")
        print(f"  签名字节长度: {sig_info['signatures_bytes_length']}")
        print(f"  期望签名字节: {sig_info['expected_signatures_bytes']}")
        print(f"  签名长度匹配: {'✅ 是' if sig_info['signatures_match'] else '❌ 否'}")
        if "signature_issues" in result:
            print(f"  ⚠️  签名问题: {len(result['signature_issues'])}个签名v值非法")
    
    if "issues" in result:
        print(f"\n⚠️  潜在问题 ({len(result['issues'])}个):")
        for i, issue in enumerate(result["issues"], 1):
            print(f"  {i}. {issue}")
    
    if result.get("type") == "AMBIGUOUS":
        print(f"\n❓ 类型模糊:")
        for type_name, info in result.get("possible_types", {}).items():
            print(f"  {type_name}: 阈值={info.get('threshold', '未知')}")
        print("  提示: 请检查metadata的完整性和格式")
    
    print("\n" + "="*80)

def main():
    """主函数"""
    # 示例metadata（您提供的）
    metadata_hex = "0x000000000000000000000000fdb9cd5f9daaa2e4474019405a328a88e7484f260ad4f6486dab3c1123361fcee187ee5512efcb527391dc50b4d2da2f3a629d7b000581e37477122a19b05329ab92a03bec7ef498e0ec4d5bf5e71931e9c770b7c3f932de07a595aa3cdc40aeca1ba2076a166834595dc1693650632ee6f0d448de58ff751be264e32aeff011fb66314aad146bc1a591c4581734a8d38d5dceb73e194a2a05637fdb1b3a6079dd6a338c57614a833d707bd45c358080ea2520f4664e24f3bd1cb3d39bf3d6a2e1e7865fcd518f0a9451d90774af5da66fdc520a868aeccd9fce20bf7572e5f24eabd48f7ab3dea4ab30692b6543f76ba9ee5390e4eb315a48e41ce52876bfb4b7221fe60415bf7e17172c6ae32e2ef23847742a67f66f92cd48612739c15e5dcad92325261b18b7326a344d0d17f62fe75a2c27fcd5b5c6f3b1c61c"
    
    print("正在分析Hyperlane metadata...")
    print(f"输入metadata长度: {len(metadata_hex)} 字符")
    
    try:
        result = analyze_metadata(metadata_hex)
        print_analysis(result)
        
        # 根据分析结果提供建议
        print("\n💡 建议:")
        if result.get("type") == "MerkleRootMultisig":
            print("  • 这是MerkleRootMultisig类型，包含完整的MerkleProof")
            print("  • 验证阈值: {}个签名".format(result.get("threshold", "未知")))
            if result.get("parsed_fields", {}).get("proof_is_zero"):
                print("  ⚠️  注意: MerkleProof部分全为零，可能需要重新计算")
        elif result.get("type") == "MessageIdMultisig":
            print("  • 这是MessageIdMultisig类型，轻量化无Proof")
            print("  • 验证阈值: {}个签名".format(result.get("threshold", "未知")))
        elif result.get("type") == "AMBIGUOUS":
            print("  • 类型模糊，请手动确认:")
            for type_name, info in result.get("possible_types", {}).items():
                print(f"    - {type_name}: 需要{info.get('threshold')}个签名")
        
    except Exception as e:
        print(f"❌ 分析失败: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()