# 特别备注："调用completeInboundQueuedTransfer完成入站转账"该功能未测试，正式启用前必须小额测试一笔

该方法是用于完成因速率限制而排队的入站转账，输入参数为digest。调用前需要去目标链的ntt manager实际执行合约确认该方法的调用权限是仅owner可以调用还是任何地址都可以调用。
虫洞文档：https://wormhole.com/docs/products/token-transfers/native-token-transfers/reference/manager/evm/#completeinboundqueuedtransfer:~:text=OutboundTransfer%20%E5%B7%B2%E5%8F%96%E6%B6%88-,completeInboundQueuedTransfer,-%EF%BC%83


# Wormhole NTT Bridge 跨链自动化脚本使用说明

## 一、简介

本项目为 Wormhole NTT（Native Token Transfer）跨链自动化脚本，支持 Wormhole 跨链桥的全流程自动化，包括发起跨链、查询 VAA、目标链赎回、入站排队完成等。  
支持三种模式：`full_send`、`redeem_only`、`complete_inbound`。

---

## 二、环境准备

### 1. 安装依赖

请确保已安装 Python 3.7+，并安装依赖库：


```bash
pip install web3 pyyaml python-dotenv requests
```

### 2. 配置私钥

将你的私钥以环境变量方式提供，例如在 `.env` 文件中添加：

```
PRIVATE_KEY=你的私钥
```

或者在运行前导出环境变量：

```bash
export PRIVATE_KEY=你的私钥
```

---

## 三、配置文件说明

请根据实际链和合约信息，编辑 `config.yaml`，主要参数说明如下：

- `mode`: 运行模式，支持 `full_send`、`redeem_only`、`complete_inbound`
- `src`: 源链信息，包括 RPC、合约地址、ABI 路径等
- `dst`: 目标链信息，包括 RPC、transceiver 列表、manager 合约等
- `method`: 合约调用方法名，如 `transfer`、`receiveMessage` 等，需要根据代币项目方部署的合约 ABI 确定。
- `token`: 跨链代币信息
- `transfer_params`: 跨链参数（金额、接收地址等）
- `auth`: 私钥环境变量名
- `runtime`: WormholeScan API 相关参数
- `logging`: 日志配置
- `src_tx_hash`: redeem_only模式下必须填写源链 tx hash，complete_inbound 选填
- `digest`: complete_inbound 模式下可选填（源链哈希和digest二选一填）

**Wormhole chain id**
具体查看此文档https://wormhole.com/docs/products/reference/chain-ids/



---

## 四、运行方式

### 1. full_send 模式（发起跨链-查询vaa-目标链执行）

适用于从头发起一次完整 Wormhole NTT 跨链：

```bash
python3 nttbridge.py
```

配置文件需设置 `mode: "full_send"`，其余参数按实际填写。

---

### 2. redeem_only 模式（查询vaa-目标链执行）

适用于已发起跨链，只需在目标链赎回并完成流程：

```bash
python3 nttbridge.py
```

配置文件需设置 `mode: "redeem_only"`，并填写 `src_tx_hash`。

---

### 3. complete_inbound 模式（已赎回但排队，主动完成入站）

适用于目标链已提交赎回但还在排队，需要主动完成入站：

```bash
python3 nttbridge.py
```

配置文件需设置 `mode: "complete_inbound"`，并填写 `digest`（如已知），或填写 `src_tx_hash` 由脚本自动获取 digest。

---

## 五、日志与排错

- 日志文件路径和级别可在 `config.yaml` 的 `logging` 部分配置。


---

## 六、常见问题

1. **私钥安全**：请勿将私钥上传或泄露，仅本地 `.env` 文件或环境变量中保存。
2. **RPC 节点可用性**：确保配置的 RPC 节点可用且同步正常。
3. **ABI 文件**：请确保 ABI 路径正确，且与合约版本匹配。配置文件里的合约地址是代理合约地址，ABI文件是实际执行合约的ABI。

---
