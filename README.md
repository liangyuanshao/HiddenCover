# HiddenCover

HiddenCover 是一个无状态匿名凭证撤销研究原型。实现采用 Rust、BLS12-381、BBS 多消息签名和共享响应证明；Cover 侧使用移植到同一标量域的 Groth--Kohlweiss 型 One-out-of-Many 证明。本仓库仅包含协议代码、测试、基准程序、对比补丁和实验数据，尚未经过生产级安全审计。

## 已实现模块

- `src/tree.rs`：完全二叉树、叶分配和 Complete Subtree Cover。
- `src/credential.rs`：逐路径 BBS 签名及隐藏签名持有证明。
- `src/oom.rs`：同域 One-out-of-Many 证明。
- `src/protocol.rs`：Setup、Issue、Revoke、Show、Verify 与状态签名。
- `src/lib.rs`：合法展示、撤销拒绝、旧状态、重放、承诺/Cover 篡改和填充攻击测试。
- `src/bin/benchmark.rs`：状态同步、公共状态、完整展示、瓶颈分解与凭证开销基准。
- `evaluation/`：基线版本、comparison patch、工作负载、原始/归一化数据和 QA 元数据。
- `scripts/analyze_and_plot.py`：跨方案归一化、数值断言和评估图表生成。

## 实现约束

1. BBS 签名知识证明中节点消息的 Schnorr 盲化量和响应与 Pedersen 承诺证明共享，从而证明两侧隐藏的是同一节点值；
2. 固定序列化格式、域分离标签和安全参数；
3. 当前状态通过纯内存公告板提供，可进一步接入区块链或透明日志适配器；
4. 测试向量检查两个证明确实绑定同一 `B`、`t`、`D_t` 与 `nonce`。

Groth--Kohlweiss 部分依据 MIT 许可的 `one-of-many-proofs` 原型结构改写，并统一使用 BLS12-381/Arkworks 标量域。

## 对比基线

- [ALLOSAUR](https://github.com/sam-jaques/allosaurust)，固定于提交 `5bf8724963529f6ca947316466ce38c0104a3dcf`。本仓库复现其持有者撤销同步和服务器更新的可比片段；修改记录见 `evaluation/patches/allosaur-comparison.patch`。
- [zkRevoke](https://github.com/praveensankar/zkRevoke)，固定于提交 `852f85846e98dd199289eeaa7943e19956a2649f`。本仓库复现其撤销公共状态和当前状态证明的可比片段；修改记录见 `evaluation/patches/zkRevoke-comparison.patch`。

这些结果是按协议语义对齐的组件级比较，不把不同方案中缺失的步骤记作实测零开销，也不宣称完整部署的端到端等价。

## 复现

Windows 下建议使用 Rust stable GNU 工具链和独立的 ASCII 构建目录：

```powershell
$env:CARGO_TARGET_DIR='C:\codex_build\hiddencover'
$env:RUSTFLAGS='-C target-cpu=native'
cargo +stable-x86_64-pc-windows-gnu test --lib
cargo +stable-x86_64-pc-windows-gnu run --release --bin benchmark -- benchmarks/results all
python -m pip install matplotlib numpy pandas
python scripts/analyze_and_plot.py
```

HiddenCover 原始输出位于 `benchmarks/results/`，统一数据与复现元数据位于 `evaluation/`。绘图脚本默认使用仓库中已保存的 ALLOSAUR 原始样本；如需从 Criterion 输出重新归一化，可将环境变量 `HIDDENCOVER_ALLO_CRITERION` 指向 Criterion 结果目录。`external/` 仅用于本地检出基线仓库，不纳入版本控制。
