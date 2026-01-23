飞书笔记：[产品文档——hyperlane跨链](https://rico-party.feishu.cn/docx/QM6MdC2EloNklhxcZC3czeXmnL4)

官方文档说可以使用 [Hyperlane CLI](https://docs.hyperlane.xyz/docs/reference/developer-tools/cli)自己[转发 EVM→EVM 消息](https://docs.hyperlane.xyz/docs/resources/message-debugging#relaying-an-evm-evm-message-yourself)，仓库代码[typescript/cli](https://github.com/hyperlane-xyz/hyperlane-monorepo/tree/main/typescript/cli)。

负责实现 hyperlane status --relay 逻辑的核心文件是 [message.ts](https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/typescript/cli/src/status/message.ts)。他不是 CLI 本地实现的方法，而是文件开头从 Hyperlane SDK 导入的核心类方法。

Hyperlane Typescript SDK[文档](https://docs.hyperlane.xyz/docs/reference/developer-tools/typescript-sdk/overview#hyperlane-typescript-sdk)、[仓库](https://github.com/hyperlane-xyz/hyperlane-monorepo/tree/main/typescript/sdk)——hyperlane跨链全流程的具体代码实现逻辑需要查看这里。

# hyperlane跨链脚本设计流程

[跨链流程图示](https://docs.hyperlane.xyz/docs/operate/validators/run-validators#design-reference)

分成 4 个阶段：

## 1. 发送阶段（Source Chain）

### 发起跨链交易：

调用代币项目方部署的跨链合约的**transferRemote** 或者类似方法

### 源链的交易完成之后需要通过RPC节点获取以下事件：

#### Dispatch事件

address=[Hyperlane v3: Mailbox Proxy](https://docs.hyperlane.xyz/docs/reference/addresses/deployments/mailbox)合约地址

topic0=0x769f711d20c679153d382254f59892613b58a97cc876b249134ac25c80f9c814

data=目标链提交跨链交易所需的message

#### InsertedIntoTree事件

address=[Hyperlane: Merkle Tree Hook](https://docs.hyperlane.xyz/docs/reference/addresses/deployments/merkleTreeHook)合约地址

topic0=0x253a3a04cab70d47c1504809242d9350cd81627b4f1d50753e159cf8cd76ed33

data=messageId和index（用于构造metadata和获取validator的签名）

## 2. 链下收集与安全证明生成

Validator是一个链下节点程序，它会：

* 监听链上 Mailbox 的 Dispatch 事件

* 识别 message

* 根据 ISM 安全模型生成相应的“安全证明/签名数据”，并把这些数据写入一个**公开可读的存储位置**（如 S3、GWS 等）

## 3. 消息传递/Relaying（Relayer 角色）

Relayer 的角色：

* 监听源链的 Dispatch 事件

* 拿到 messageId + message

* 根据对应的 ISM 类型：拉取 Validator 提供的签名/证明或调用链下 API或等待链下安全机制完成（如 OP Stack）构造出目标链所需的 metadata

### 脚本需要做的事

确定ISM类型，确定validator及其签名存储位置，根据ISM类型和获取到的签名构造metadata

#### ISM分类及对应metadata格式

##### [Multisig ISM](https://docs.hyperlane.xyz/docs/protocol/ISM/standard-ISMs/multisig-ISM)

[hyperlane文档](https://docs.hyperlane.xyz/docs/protocol/ISM/standard-ISMs/multisig-ISM#merklerootmultisigismmetadata)：分为两种MERKLE_ROOT_MULTISIG和MESSAGE_ID_MULTISIG，已写脚本：[**metadata.py**](https://github.com/rootdiae/rootdiae_python_scripts/blob/main/HyperlaneBridge/metadata.py)（输入验证者签名用于生成metadata）和[**metadata_check.py**](https://github.com/rootdiae/rootdiae_python_scripts/blob/main/HyperlaneBridge/metadata_check.py)（用于判断metadata的类型）

[hyperlane SDK源码multisig.ts](https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/typescript/sdk/src/ism/metadata/multisig.ts)：

目前只支持message id 类型的metadata, [Merkle proofs are not yet supported](https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/9116ab0a378ebc24a8be217527f987aee1c866b2/typescript/sdk/src/ism/metadata/multisig.ts#L161)

[按序取](https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/9116ab0a378ebc24a8be217527f987aee1c866b2/typescript/sdk/src/ism/metadata/multisig.ts#L195)验证者的签名，只取达到阈值的前n个（这里的顺序是指从ism合约返回的validator列表的顺序）

##### [routing-ISM](https://docs.hyperlane.xyz/docs/protocol/ISM/standard-ISMs/routing-ISM)

[hyperlane SDK源码routing.ts](https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/typescript/sdk/src/ism/metadata/routing.ts)：还没有去看，**脚本实现必看**

##### [aggregation-ISM](https://docs.hyperlane.xyz/docs/protocol/ISM/standard-ISMs/aggregation-ISM)

[hyperlane SDK源码aggregation.ts](https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/typescript/sdk/src/ism/metadata/aggregation.ts)

嵌套的子 AggregationISM 的元数据，依然遵循 AggregationISM 的元数据打包规则，由它自己的子 ISM 信息打包生成。

**示例**

子ism为3，阈值为2，只要达到阈值即可，允许子ism构造失败

假设有 3 个子模块，阈值=2，只有模块0和模块2成功：

构建过程：

模块0成功：元数据 0xaaaa (2字节)

模块1失败：null

模块2成功：元数据 0xbbbbbb (3字节)

最终编码：

text

范围表（3个子模块 × 2个位置 × 4字节 = 24字节）：

偏移量 0-3:   0x00000018 (十进制24)  # 模块0起始：跳过24字节范围表

偏移量 4-7:   0x0000001A (十进制26)  # 模块0结束：24+2=26

偏移量 8-11:  0x00000000             # 模块1起始：0表示不存在

偏移量 12-15: 0x00000000             # 模块1结束：0

偏移量 16-19: 0x0000001A (十进制26)  # 模块2起始：从26开始

偏移量 20-23: 0x0000001D (十进制29)  # 模块2结束：26+3=29

数据部分：

偏移量 24-25: 0xaaaa    # 模块0元数据

偏移量 26-28: 0xbbbbbb  # 模块2元数据

##### [offchain-lookup-ISM](https://docs.hyperlane.xyz/docs/protocol/ISM/standard-ISMs/offchain-lookup-ISM)

[hyperlane SDK源码ccipread.ts](https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/typescript/sdk/src/ism/metadata/ccipread.ts)：还没有去看，**脚本实现必看**

目标链的 Offchain Lookup ISM 通过主动抛出`OffchainLookup`异常，向relayer传递了完成链下查询的全部必要信息；中继器严格按照这些信息调用指定的链下 API；API 会返回JSON 数据，就是最终要传入目标链 Mailbox 合约函数的`metadata`参数。

#### 链上实现多层嵌套需递归获取

链上实际实现一般是多种ism层层嵌套，需要通过脚本递归获取路径上和最终执行的ISM合约地址、类型、阈值及validator和签名存储位置

已写脚本[**ism_and_validator.py**](https://github.com/rootdiae/rootdiae_python_scripts/blob/main/HyperlaneBridge/ism_and_validator.py)

##### 问题：validator是获取目标链上的还是获取源链上的

从跨链流程来看，源链只负责发起交易，只有目标链的ism来验证metadata，所以应该是由目标链ism查到的validator来负责监听源链事件并签名。

但是在运行脚本(get_valiator_signature.py)[https://github.com/rootdiae/rootdiae_python_scripts/blob/main/HyperlaneBridge/get_valiator_signature.py]时，用源链上的validator地址获取到的最新签名出现在了目标链已提交的metadata数据里。

这个需要去hyperlane的SDK里确认validator是从哪里获取的。

#### validator签名存储位置

通过RPC节点调用链上 [ValidatorAnnounce 合约](https://docs.hyperlane.xyz/docs/reference/addresses/deployments/validatorAnnounce)的[getAnnouncedStorageLocations方法](https://etherscan.io/address/0x9bBdef63594D5FFc2f370Fe52115DdFFe97Bc524#readContract#F1)获取

##### 问题：对应ISM合约validator的阈值数量大于有签名存储位置的validator数量

预期应该是每个validator都有自己的签名存储位置，从每个位置里取出有签名的再拼接成metadata，或至少有和阈值相等的签名存储位置。

示例说明：总共有5个validator，阈值为3，但是实际上只有1个validator可以查到存储位置。

##### 文档描述：

[https://docs.hyperlane.xyz/docs/operate/validators/run-validators#production-setup-aws](https://docs.hyperlane.xyz/docs/operate/validators/run-validators#production-setup-aws)

* 尚未宣布——那relayer是从哪里获得到签名数据的？

If your Validator has not yet announced itself, and does not have enough tokens to pay for gas, it will log a message specifying how many tokens are needed.

* 密钥、aws账户、s3存储桶可以被多个验证者使用

Running Multiple Validators: Key Considerations

The same checkpoint syncer S3 bucket can be used by multiple validators, however each must use a different folder

同一个检查点同步器的 S3 桶可以被多个验证者使用，但每个都必须使用不同的文件夹。

——但是从合约查到的存储位置都是具体到文件夹的S3存储位置

#### validator签名获取

[hyperlane SDK源码multisig.ts](https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/a7bc6bea84edc11eab5c91497a6b091b0ac08aa3/typescript/sdk/src/ism/metadata/multisig.ts)这份代码的逻辑流程是加载配置文件、获取源链交易的事件、拉取并筛选检查点、验证阈值、提取签名、按格式编码。

需要明确这里的配置文件是从哪里来的，他包含ism合约、验证者列表及存储位置。

需要明确这里的拉取并筛选检查点的具体逻辑，是通过什么方法拉取的，又是如何实现筛选的。

（index 的来源：index 是消息在源链 MerkleTreeHook 合约中的「Merkle 索引」—— 每个消息被插入 Merkle 树时，会触发 Inserted 事件，事件中包含 index 参数。

拉取逻辑：验证者会为每个 index 生成一个独立的检查点文件，存储路径为：s3://<bucket>/<prefix>/<index>.json

SDK 传入 index 后，S3 客户端会拼接上述路径，调用 GetObjectCommand 拉取对应文件。）

##### 问题：是否可以直接通过源链交易里的index直接索引到validator的签名文件

脚本[**get_valiator_signature.py**](https://github.com/rootdiae/rootdiae_python_scripts/blob/main/HyperlaneBridge/get_valiator_signature.py)获取验证者签名的逻辑是用二分法实现快速索引validator最新的n个签名文件。获取到签名文件后，可以用message id去hyperlane浏览器查到这笔跨链交易，可以观察到签名文件名里的idx和文件里的index与源链交易logs里的index是一致的。

在SDK的拉取逻辑里应该是直接通过源链交易里的index直接索引到validator的签名文件，需要看[具体代码](https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/a7bc6bea84edc11eab5c91497a6b091b0ac08aa3/typescript/sdk/src/ism/metadata/multisig.ts)确认。

## 4. 接收阶段（Destination Chain）

### 提交跨链交易

目标链调用Hyperlane v3: Mailbox Proxy合约的**process**方法，输入参数为构造的**metadata**和源链rpc获取到的**message**即可。

