# 特别备注："调用completeInboundQueuedTransfer完成入站转账"该功能未测试，正式启用前必须小额测试一笔

该方法是用于完成因速率限制而排队的入站转账，输入参数为digest。调用前需要去目标链的ntt manager实际执行合约确认该方法的调用权限是仅owner可以调用还是任何地址都可以调用。
虫洞文档：https://wormhole.com/docs/products/token-transfers/native-token-transfers/reference/manager/evm/#completeinboundqueuedtransfer:~:text=OutboundTransfer%20%E5%B7%B2%E5%8F%96%E6%B6%88-,completeInboundQueuedTransfer,-%EF%BC%83


# Wormhole 跨链转账脚本

## 概述

这是一个用于 Wormhole 跨链网络的自动化脚本，支持从 EVM 链向 EVM 链转移 NTT 模式的代币。脚本提供三种操作模式，涵盖从发起跨链到最终完成的完整流程。

## 功能特性

1. **三种操作模式**：
   - `full_send`: 完整的跨链流程（授权 → 发起跨链 → 监控VAA → 目标链执行）
   - `redeem_only`: 仅执行目标链的赎回操作（监控VAA → 目标链执行；需要源链交易哈希）
   - `complete_inbound`: 完成已在目标链排队的转账（目标链已执行但在队列中，主动完成入站）

2. **自动化监控**：
   - 自动轮询 WormholeScan API 获取 VAA
   - WebSocket 实时监听目标链事件
   - 智能判断交易状态，避免重复执行

3. **容错机制**：
   - 自动重连失败的 WebSocket 连接
   - 多节点轮询确保稳定性
   - 完善的错误处理和日志记录

## 环境要求

### Python 版本
- Python 3.8+

### 依赖库
```bash
pip install web3 pyyaml requests python-dotenv eth-abi eth-utils websockets
```

### 环境变量
创建 `.env` 文件或在系统环境变量中设置：
```
PRIVATE_KEY=你的以太坊私钥（0x开头）
```

## 配置文件说明

### 主要配置项

请根据实际链和合约信息，编辑 `config.yaml`，主要参数说明如下：

- `mode`: 运行模式，支持 `full_send`、`redeem_only`、`complete_inbound`
- `src`: 源链信息，包括 RPC、合约地址、ABI 路径等，其中`wormhole_chain_id`为虫洞的链ID，具体查看此[文档](https://wormhole.com/docs/products/reference/chain-ids/)
- `dst`: 目标链信息，包括 RPC、transceiver 列表、manager 合约等,`wss_endpoints`为目标链的 WebSocket 端点列表，用于实时监听事件，必须保证所使用的端点数据及时且准确。`threshold`为目标链manager合约的getThreshold方法中的返回值。
- `methods`: 合约调用方法名，如 `transfer`、`receiveMessage`、`MessageAttestedTo`等等，都需要根据代币项目方部署的合约 ABI 确定。
- `token`: 跨链代币信息，其中`wormhole_declaims`，一般情况下为8，可在[虫洞api](https://wormholescan.io/#/developers/wormholescan-doc/api-doc/get-vaas?network=Mainnet)查看他人该代币的跨链交易Responses里的"decimals".
- `transfer_params`: 跨链参数（金额、接收地址等），full_send模式下，源链发起跨链交易需要注意参数顺序，需要与合约ABI中的方法参数顺序一致。可定位代码文件中“# 需要根据实际方法参数调整顺序”注释处调整。`amount`为实际转移的代币数量，如果是通过executor发起的跨链，此处填写的是源链交易里to Null地址的代币数量，一般是会少千分之一。
- `auth`: 私钥环境变量名
- `runtime`: WormholeScan API 相关参数
- `logging`: 日志配置
- `src_tx_hash`: redeem_only模式下必须填写源链 tx hash，complete_inbound 模式下可选填
- `digest`: complete_inbound 模式下可选填（源链哈希和digest二选一填）

**Wormhole chain id**
具体查看此文档https://wormhole.com/docs/products/reference/chain-ids/


## 使用指南

### 1. 准备阶段

```bash

# 安装依赖
pip install -r requirements.txt
# 或手动安装
pip install web3 pyyaml requests python-dotenv eth-abi eth-utils websockets

# 设置私钥
echo "PRIVATE_KEY=你的私钥" > .env
```

### 2. 配置文件设置

根据你的需求编辑 `config.yaml`：

**重要参数**：
- 确认 RPC 和 Websocket 端点可用
- 检查合约地址正确性，配置文件里的合约地址是代理合约地址，ABI文件是实际执行合约的ABI。
- 确认ABI文件路径正确
- 设置正确的跨链参数（金额、接收地址等）

### 3. 运行脚本

#### 模式 1: full_send（完整流程）
```bash
# 修改配置文件 mode: "full_send"
python nttbridge.py
```
**适用场景**：从头开始执行完整的跨链转账

#### 模式 2: redeem_only（仅赎回）
```bash
# 修改配置文件
# mode: "redeem_only"
# src_tx_hash: "0x你的源链交易哈希"

python nttbridge.py
```
**适用场景**：已经发起了跨链转账，需要执行目标链的赎回操作

#### 模式 3: complete_inbound（完成入站）
```bash
# 修改配置文件
# mode: "complete_inbound"
# digest: "你的digest" 或 src_tx_hash: "你的交易哈希"

python nttbridge.py
```
**适用场景**：VAA 已提交但交易仍在队列中，需要手动完成入站

### 4. 监控日志

脚本会生成详细的日志文件 `wormhole.log`，包含：
- 交易状态
- VAA 获取进度
- WebSocket 连接状态
- 错误信息（如有）

## 注意事项

### 1. 私钥安全
- 私钥仅存储在本地环境变量中
- 不要将私钥提交到版本控制系统
- 使用专用钱包进行跨链操作

### 2. 网络稳定性
- 确保 RPC 和 WebSocket 端点稳定
- 建议配置多个备用节点
- 关注 Gas 价格波动

### 3. 资金安全
- 首次使用建议小额测试
- 确认接收地址正确无误
- 注意跨链手续费

## 高级配置

### 自定义 ABI 文件
脚本需要以下 ABI 文件：
- `./abi/manager_src.json`: 源链管理器实际执行合约的完整 ABI
- `./abi/manager_dst.json`: 目标链管理器实际执行合约的完整 ABI
- `./abi/transceiver_a.json`: transceiver 实际执行合约的完整 ABI（如有多个transceiver，为确保正确调用，最好每个都配置单独的ABI文件）

请确保这些文件存在且内容正确。

### 日志级别
修改配置文件中的 `log_level` 获取更多信息：
- `DEBUG`: 最详细，用于调试
- `INFO`: 常规运行信息（推荐）
- `WARNING`: 仅警告和错误
- `ERROR`: 仅错误信息
