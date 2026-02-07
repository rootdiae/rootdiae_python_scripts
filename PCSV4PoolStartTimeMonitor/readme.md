# PCSV4PoolStartTimeMonitor 监控程序

## 项目概述

这是一个用于监控 BSC 链上 `PoolStartedAtUpdated` 事件的自动化程序。该程序会定期查询指定合约的事件，解析池子信息，并将数据同步到飞书表格，同时通过钉钉发送通知。

## 功能特点

1. **事件监控**：定期查询指定合约的 `PoolStartedAtUpdated` 事件
2. **数据解析**：自动解析事件中的池子ID、开始时间等信息
3. **池子信息查询**：根据池子ID查询对应的代币信息（currency0和currency1）
4. **飞书集成**：将事件和池子信息保存到飞书表格
5. **钉钉通知**：发送事件通知、池子信息通知等
6. **本地持久化**：保存已处理的区块号、待查询池子列表等信息到本地文件，确保程序重启后能够继续运行
7. **多节点轮询**：支持多个RPC节点轮询，提高可用性和稳定性 
8. **自动重试**：API调用失败时自动重试，最大重试次数为配置值

## 安装依赖

```bash
pip install lark-oapi -U
```

### 依赖库

- `requests`: HTTP请求处理
- `web3`: 以太坊/Bsc交互
- `lark-oapi`: 飞书API
- `python-dotenv`: 环境变量管理（可选）

## 配置说明

程序的主要配置位于代码顶部的常量定义部分，需要根据实际情况修改：

### 1. RPC配置

```python
# 2.1 RPC配置（多节点轮询，无认证，需要配置支持大区块范围查询eth_getLogs的节点）
RPC_ENDPOINTS = [
    "https://bsc.drpc.org",
    "https://bsc-rpc.publicnode.com",
    "https://wallet.okex.org/fullnode/bsc/discover/rpc"
]
RPC_TIMEOUT = 10  # 单次请求超时时间（秒）
RPC_RETRY_TIMES = 5  # 重试次数
```

### 2. 钉钉配置

```python
# 2.2 钉钉配置（硬编码，无加签，需替换为实际Webhook）
DINGTALK_WEBHOOK = "https://oapi.dingtalk.com/robot/send?access_token=your_token_here"
DINGTALK_TIMEOUT = 5  # 钉钉请求超时（秒）
DINGTALK_RETRY_TIMES = 3  # 钉钉重试次数
```

### 3. 合约与事件配置

```python
# 2.3 合约与事件配置
# PoolStartedAtUpdated事件相关
EVENT_ADDRESS = Web3.to_checksum_address("0x72e09eBd9b24F47730b651889a4eD984CBa53d90").lower()
EVENT_TOPIC0 = "0xcaccc4bc886d75b13de806bf4292e4cc78a042eae40849e6a96242f7d03cb5fb".lower()

# poolIdToPoolKey合约1：CLPoolManager合约
POOL_KEY_CONTRACT1 = Web3.to_checksum_address("0xa0FfB9c1CE1Fe56963B0321B32E7A0302114058b").lower()
# poolIdToPoolKey合约2：BinPoolManager合约
POOL_KEY_CONTRACT2 = Web3.to_checksum_address("0xc697d2898e0d09264376196696c51d7abbbaa4a9").lower()
```

### 4. 飞书配置

```python
# 2.4 飞书配置（硬编码，需替换为实际AppID/Secret/Token）
FEISHU_APP_ID = "your_app_id"    # 飞书应用的App ID
FEISHU_APP_SECRET = "your_app_secret"  # 飞书应用的App Secret
FEISHU_APP_TOKEN = "your_app_token"  # 飞书表格链接的App Token,确保应用有编辑表格权限（目标表格右上...更多添加文档应用）
FEISHU_TABLE_ID = "your_table_id"  # 飞书表格的Table ID
FEISHU_RETRY_TIMES = 3  # 飞书API重试次数 
```
示例：https://rico-party.feishu.cn/base/EzBRbMO9MaBdFTscTh3cPKGunfh?table=tblUj6QPa0JhJzbI&view=vewERhEB4H
FEISHU_APP_TOKEN = "EzBRbMO9MaBdFTscTh3cPKGunfh"
FEISHU_TABLE_ID = "tblUj6QPa0JhJzbI"

## 使用方法

### 运行程序

```bash
python monitor.py
```

程序将在后台持续运行，执行以下操作：

1. **初始化**：
   - 配置日志系统
   - 初始化飞书客户端
   - 加载或创建必要的本地文件

2. **事件查询**：
   - 每30分钟查询一次 `PoolStartedAtUpdated` 事件
   - 解析事件数据
   - 将新事件保存到飞书表格
   - 发送钉钉通知

3. **池子查询**：
   - 开盘前2小时内，每10分钟查询一次池子信息
   - 开盘前2小时前，整点查询一次池子信息
   - 开盘后，仅查询一次
   - 查询到池子信息后，更新飞书表格并发送钉钉通知

## 钉钉通知发送时机

1. **程序启动时**：发送程序启动通知
2. **事件解析失败时**：当解析`PoolStartedAtUpdated`事件失败时发送通知
3. **新事件通知**：当查询到新的`PoolStartedAtUpdated`事件时发送通知
4. **池子信息通知**：当成功查询到池子信息（包括代币符号和地址）时发送通知

## 飞书文档更新时机

1. **新事件处理时**：将新查询到的事件创建为飞书表格记录
2. **事件更新时**：当同一池子ID的事件有更新（区块号更大）时，更新飞书表格中的交易哈希和开始时间字段
3. **池子信息查询后**：当成功查询到池子的代币信息后，更新飞书表格中的代币地址和符号字段
4. **过了开盘时间时**：当池子已过开盘时间且不再查询时，更新飞书表格记录的remark字段

## 特殊情况处理

1. **RPC请求失败**：
   - 自动切换到下一个RPC节点（轮询机制）
   - 最多重试`RPC_RETRY_TIMES`次
   - 重试失败后记录错误日志

2. **合约调用失败**：
   - 对于`poolIdToPoolKey`方法，先尝试调用第一个合约，失败后尝试第二个合约
   - 捕获合约逻辑错误，避免程序崩溃
   - 最多重试`RPC_RETRY_TIMES`次

3. **零地址处理**：
   - 当且仅当任一代币地址为零地址（`0x0000000000000000000000000000000000000000`）时，返回代币符号"BNB"

4. **飞书API调用失败**：
   - 自动重试`FEISHU_RETRY_TIMES`次
   - 重试失败后记录错误日志

5. **文件读写失败**：
   - 尝试多次（最多3次）保存文件
   - 读写失败时使用默认值，确保程序继续运行

## 去重逻辑

1. **事件去重**：
   - 在事件查询时，对于同一池子ID（`poolId`），只保留区块号最大的事件
   - 确保池子的开始时间是最新更新的时间

2. **本地映射表去重**：
   - 本地映射表`pool_mapping.json`记录每个池子ID对应的飞书记录ID和最新事件区块号
   - 当处理新事件时，检查区块号是否大于已记录的区块号，只有更大时才更新

3. **待查询列表去重**：
   - 待查询池子列表`pending_pools.json`使用字典结构存储，避免同一池子ID重复存在
   - 当事件更新时，自动更新待查询列表中的信息

## 代码结构

```
monitor2.py
├── 1. 日志配置
├── 2. 核心配置常量
├── 3. 工具函数
│   ├── 时间处理
│   ├── 文件操作
│   ├── RPC请求
│   ├── 合约调用
│   └── 飞书API客户端
├── 4. 钉钉通知模块
├── 5. 事件查询模块
├── 6. 池子查询模块
└── 7. 主循环模块
```

### 核心模块说明

1. **事件查询模块**：
   - `query_pool_events()`: 查询指定区块范围的事件
   - `parse_pool_event()`: 解析单个事件日志
   - `process_new_events()`: 处理新查询到的事件

2. **池子查询模块**：
   - `query_pool_key()`: 查询池子的currency0和currency1地址
   - `process_single_pool()`: 处理单个池子查询
   - `run_pool_query()`: 执行池子查询逻辑

3. **主循环模块**：
   - `main()`: 主循环，定时执行事件查询和池子查询



## 本地文件说明

1. `processed_block.json`: 记录最后处理的区块号和更新时间，确保程序重启后能够继续查询未处理的区块
2. `pool_mapping.json`: 本地映射表，记录池子ID与飞书record_id、block_number的对应关系。飞书record_id用于更新记录；block_number用于去重处理，确保池子开始时间是最后更新的时间。
3. `pending_pools.json`: 待查询池子列表，记录池子ID、开始时间、是否已查询等信息，程序会根据这个列表定期查询池子信息

## 注意事项

1. **配置安全**：请妥善保管您的钉钉Webhook、飞书AppID/Secret等敏感信息，避免泄露
2. **RPC节点**：建议使用多个可靠的RPC节点，提高程序可用性
3. **性能考量**：程序会定期发起RPC请求，请确保服务器网络稳定
4. **飞书表格权限**：确保飞书应用有足够的权限操作表格
5. **钉钉机器人设置**：请确保钉钉机器人已正确配置，并且Webhook有效

## 故障排查

1. **程序无法启动**：
   - 检查依赖是否安装正确
   - 检查配置是否正确，特别是RPC节点、钉钉Webhook等

2. **事件查询失败**：
   - 检查RPC节点是否可用
   - 检查合约地址和事件签名是否正确

3. **池子信息查询失败**：
   - 检查合约地址是否正确
   - 检查网络连接是否稳定

4. **飞书表格同步失败**：
   - 检查飞书配置是否正确
   - 检查飞书应用权限是否足够

5. **钉钉通知发送失败**：
   - 检查钉钉Webhook是否正确
   - 检查网络连接是否稳定
