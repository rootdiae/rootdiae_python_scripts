# Wormhole Token Bridge 跨链自动化脚本使用说明

## 一、简介
本项目为 Wormhole Token Bridge 跨链自动化脚本，支持 Wormhole Token Bridge 的全流程自动化，包括发起跨链、查询 VAA、目标链赎回等。
支持两种模式：full_send（发起跨链-查询vaa-目标链执行）、redeem_only（查询vaa-目标链执行）。


## 二、环境准备

1. 安装依赖
请确保已安装 Python 3.7 及以上版本，并安装依赖库：

2. 配置私钥

将你的私钥以环境变量方式提供，例如在 `.env` 文件中添加：

```
PRIVATE_KEY=你的私钥
```

或者在运行前导出环境变量：

```bash
export PRIVATE_KEY=你的私钥
```

## 三、配置文件说明

请根据实际链和合约信息，编辑 `config.yaml`，主要参数说明如下：
- `mode`: 运行模式，支持 full_send（完整跨链流程）、redeem_only（仅目标链赎回）
- `wtt_method`: 跨链调用方法，支持 transferTokens 和 transferTokensWithPayload
- `src`: 源链信息，包括 RPC、链名、wormhole 链ID、是否POA链
- `token_bridge_contract_src`: 源链 Token Bridge 合约地址
- `dst`: 目标链信息，包括 RPC、链名、wormhole 链ID、是否POA链
- `token_bridge_contract_dst`: 目标链 Token Bridge 合约地址
- `token`: 跨链代币信息，包括合约地址、精度、符号、是否需要授权
- `recipient_on_dst`: 目标链接收地址
- `amount`: 跨链数量（字符串，十进制）
- `private_key_env`: 私钥环境变量名
- `wormholescan_api_base`: WormholeScan API 地址
- `vaa_poll_interval_seconds`: VAA 轮询间隔（秒）
- `vaa_alert_interval_seconds`: VAA 警告间隔（秒）
- `vaa_alert_timeout_seconds`: VAA 超时警告（秒）
- `log_level`: 日志等级
- `payload`: 可选，transferTokensWithPayload 模式下的 payload
- `src_tx_hash`: redeem_only 模式下需要填写的源链跨链交易哈希

### Wormhole chain id
具体可参考官方文档：https://wormhole.com/docs/products/reference/chain-ids/

## 四、运行方式

### 1. full_send 模式（发起跨链-查询vaa-目标链执行）
适用于从头发起一次完整 Wormhole Token Bridge 跨链：

配置文件需设置 `mode`: "full_send"，其余参数按实际填写。

### 2. redeem_only 模式（查询vaa-目标链执行）
适用于已发起跨链，只需在目标链赎回并完成流程：

配置文件需设置 `mode`: "redeem_only"，并填写 src_tx_hash。

## 五、日志与排错
- 日志会同时输出到终端和 wormhole.log 文件，日志等级可在 config.yaml 的 log_level 字段配置。
- 常见错误如私钥未配置、RPC 不可用、余额不足、VAA 长时间未获取等，脚本会有详细日志提示。

## 六、常见问题
1. 私钥安全：请勿将私钥上传或泄露，仅本地 .env 文件或环境变量中保存。
2. RPC 节点可用性：确保配置的 RPC 节点可用且同步正常。
3. 代币授权：如需授权，脚本会自动发起 approve 交易。
4. VAA 获取慢：如长时间未获取到 VAA，请检查 Wormhole 网络和源链交易状态。
5. 目标链 claim 失败：请检查目标链 RPC、合约地址和 gas 设置。
也可去目标链的wormhole:tokenbridge合约里的`completeTransfer`方法手动执行claim，输入参数为 https://wormholescan.io/#/developers/tools/vaa-parser 这个api查询到的vaa的hex编码（前面加0x前缀，如果有多个vaa，必须提交带有guardianSignatures的vaa）。