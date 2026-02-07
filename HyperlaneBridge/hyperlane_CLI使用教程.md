# hyperlane CLI使用教程

hyperlane官方文档：https://docs.hyperlane.xyz/docs/reference/developer-tools/cli

## 先在官方的注册表里找是否有该代币
注册表链接：https://github.com/hyperlane-xyz/hyperlane-registry
deployments/warp_routes文件夹下用代币符号搜索，该代币的文件夹下会有config.yaml包含该代币的warp router。
配置文件里的chainName就是该代币的<origin-chain>和<destination-chain>

## 发起跨链交易
```bash
HYP_KEY=<your-private-key> hyperlane warp send --origin <origin-chain> --destination <destination-chain> --symbol <token-symbol> --amount <amount> --recipient <address>
```

参数说明：
--amount   为转账金额（代币最小单位，如 USDC代币精度为6，传 1000000=1USDC）
--recipient 接收地址（可选，默认是发送者地址），可以指定自定义接收地址

需要注意：
命令输入之后，如果有一个代币有多个router需要再选择warp_router，注册表里config文件名即为所需的router，键盘上下键选择后enter确定.

## 查询跨链状态
```bash
hyperlane status --origin <origin-chain> --id <message-id>
```

## 自己执行目标链claim
```bash
HYP_KEY=<your-private-key> hyperlane status --relay --origin <origin-chain> --id <message-id>
```

