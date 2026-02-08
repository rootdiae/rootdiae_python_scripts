import websockets
import json
import asyncio
from datetime import datetime
from itertools import cycle

# 此脚本用于获取rpc节点返回的原始数据

# 配置参数
#运行前先设置代理   export https_proxy=http://127.0.0.1:40880 http_proxy=http://127.0.0.1:40880 all_proxy=socks5://127.0.0.1:40880
#运行指令  ./myenv/bin/python get_rpc_data.py
# 可靠的BSC WebSocket节点（已筛选可用节点）
WS_ENDPOINTS = [
    "wss://base-mainnet.g.alchemy.com/v2/3qJGxibEgtvZTBvYvzi3l"
]

# 监听的合约地址（可不填）
ADDRESS = "0xd15274c3910600a8246C86a198DE18618Cd47401".lower()

# 事件主题（AND关系，必须是66字符的hex字符串，含0x前缀）
# 注意：每个topic必须是64字符的哈希值（加0x前缀共66字符）
TOPICS = [
    "0x35a2101eaac94b493e0dfca061f9a7f087913fde8678e7cde0aca9897edba0e5" #topic0
    #topic1,none表示为任意值
    # topic2
]

# 输出文件名称
OUTPUT_FILE = "z_MessageAttestedTo_events.txt"
RECONNECT_DELAY = 5  # 重连间隔（秒）
NODE_SWITCH_DELAY = 10  # 节点切换间隔（秒）

def validate_topics(topics):
    """验证topic格式是否正确（66字符，0x开头）"""
    for i, topic in enumerate(topics):
        if topic is None:
            continue  # None 表示该位置可以是任意值，跳过验证
        if not topic.startswith("0x") or len(topic) != 66:
            raise ValueError(f"topic {i} 格式错误：必须以0x开头且长度为66字符（实际：{len(topic)}）")
    print("主题格式验证通过")

async def handle_event(event_data):
    """处理收到的事件并写入文件"""
    event_data["received_at"] = datetime.now().isoformat()
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_data, indent=2, ensure_ascii=False) + "\n\n")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 事件写入文件，区块号: {event_data.get('blockNumber')}")

async def subscribe(websocket):
    """发送订阅请求并返回订阅ID"""
    subscribe_params = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_subscribe",
        "params": [
            "logs",
            {**({"address": ADDRESS} if ADDRESS else {}),
                "topics": TOPICS  # 多个topic为AND关系
            }
        ]
    }
    await websocket.send(json.dumps(subscribe_params))
    response = await websocket.recv()
    response_data = json.loads(response)
    
    if "error" in response_data:
        raise Exception(f"订阅失败: {response_data['error']['message']}")
    
    return response_data["result"]

async def listen(websocket, subscription_id):
    """持续监听事件推送"""
    try:
        while True:
            message = await websocket.recv()
            data = json.loads(message)
            
            if "method" in data and data["method"] == "eth_subscription":
                await handle_event(data["params"]["result"])
                
    except websockets.exceptions.ConnectionClosed:
        print("连接已关闭，准备切换节点...")
        raise  # 触发节点切换

async def connect_and_monitor(node):
    """连接到指定节点并开始监控"""
    try:
        async with websockets.connect(node) as websocket:
            print(f"已连接到节点: {node}")
            
            # 发送订阅请求
            subscription_id = await subscribe(websocket)
            print(f"订阅成功，ID: {subscription_id}")
            
            # 开始监听事件
            await listen(websocket, subscription_id)
            
    except Exception as e:
        print(f"节点 {node} 发生错误: {str(e)}")
        raise  # 触发节点切换

async def main():
    """主逻辑，实现节点轮询机制"""
    # 先验证topic格式
    try:
        validate_topics(TOPICS)
    except ValueError as e:
        print(f"配置错误: {e}")
        return
    
    # 创建节点循环迭代器
    node_cycle = cycle(WS_ENDPOINTS)
    
    while True:
        # 获取下一个节点
        current_node = next(node_cycle)
        
        try:
            await connect_and_monitor(current_node)
        except Exception as e:
            print(f"节点 {current_node} 连接失败或异常")
            print(f"{NODE_SWITCH_DELAY}秒后尝试下一个节点...")
            await asyncio.sleep(NODE_SWITCH_DELAY)

if __name__ == "__main__":
    try:
        print("事件监控脚本启动中...")
        print(f"监控的主题: {TOPICS}")
        print(f"输出文件: {OUTPUT_FILE}")
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户终止程序")
    except Exception as e:
        print(f"程序异常退出: {str(e)}")
    