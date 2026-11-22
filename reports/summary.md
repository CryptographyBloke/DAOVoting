# T004 — Same-circuit scheduler comparison

本报告是本任务唯一的人类可读报告。2026-11-22 的 20 次正式计票全部通过独立公开验证与隔离 oracle 比对。正文以正式运行的原始 manifest 为准；前期冒烟测试不进入统计。论文、既有云端/多机结果、链上回执及 v0.2.0 均未修改。

## 1. Research question

原实验展示了 dataflow 执行与参考深度公式，但尚无实际运行的参考调度可供控制比较。本任务比较同一个加密加权阈值电路的两种执行策略，测量门依赖、批处理与线程利用对加密计票墙钟时间的共同影响。比较对象是本仓库内的调度策略，不是 CGY 作者的软件，也不是不同投票功能之间的速度排名。

## 2. Baseline definition

**Level-serial reference scheduling（reference）**：平衡加法树中，每个 ripple adder 按构造顺序 `p0,p1,q1,p2,q2,...` 推进；同一树层的不同 adder 独立推进，可并行执行。整个树层完成才开启下一层。聚合后串行推进阈值减法器，最后执行原终端释放。没有将所有门强行全局串行，也没有增加每个门序号的全局屏障。

**Dataflow scheduling（dataflow，默认）**：保留现有 as-soon-as-ready 行为，输入密文就绪即可启用条件门，没有额外树层屏障。

两者使用同一个 `Arc<Circuit>` 所定义的 DAG、门编号、仿射运算、输入顺序、BabyJubjub ElGamal、CGY CSZ/重随机化/部分解密证明，以及 `C_b = E_1 - Q` 终端适配。委员会保持 `(a,t,q_dec)=(5,4,5)`。每次配对共享同一 setup、CRS、秘密份额、选票、权重、阈值和封存 board；计票贡献使用新随机性。最终 transcript 可以不同，接受谓词不变。

参考策略只控制生产者派发；公开 verifier 继续接受任何满足原协议依赖的有效 transcript，不需要信任调度标签。参考策略的运行时检查在逐门前驱和树层屏障上实施，而非用深度乘单门耗时估算。

## 3. Implementation changes

本任务在保留真实上游历史的既有 clone（`C:/Users/31831/AppData/Local/Temp/Voting-T002-upstream-objects/authentic-clone`）开发与提交。`D:/31831/Desktop/Voting` 保留既有稿件和历史工作区，本次在那里保存报告、小型公开索引及原始结果；未覆盖其已有未提交文件。

测量用源码提交：`c6804f3ef6ae6eaf7d33f5741745885cbf1fedfb`，基于 v0.2.0 的 `6bfe47b77c94e6c8d5de21657dc65f5cc4821dd2`。正式运行的所有 manifest 均记录 `source_dirty=false`。本报告和小型公开索引在测量完成后加入；未再次改变测量源码。

| 文件 | 修改与责任 |
|---|---|
| `src/circuit.rs:12,243,278` | Scheduler 枚举；从既有门顺序导出 reference 前驱/树层/深度；共同 DAG 不变。 |
| `src/tally.rs:278,357,509,579` | 开始前选择生产策略，门前驱与树层派发限制；统计首个 masking 批次；沿用原有 prove/check/apply。 |
| `src/experiment.rs:139,415` | 统一计时；一次 setup/prove/admit 后复制相同输入；交替顺序；记录来源、批次和公开哈希；验证与 oracle 均通过才写成功记录。 |
| `src/main.rs:89,268,333` | `tally --scheduler reference\|dataflow`；`experiment --scheduler both`；顺序偏移和机器信息；汇总新增字段。 |
| `tests/e2e.rs:31` | 配对运行、公开文件独立回放、错误 claim 与破坏 transcript 的拒绝。 |
| `reproduce.ps1:20,181` | `-SchedulerComparison -SchedulerThreads 24`；同机 local-only 配对，n=1024 强制一次，跨规模交替；沿用唯一目录与退出码处理。 |
| `README.md` | 新调度命令、范围和计时边界。 |
| `evidence/schedulers.json` / `reports/summary.md` | 小型公开测量索引与本报告；大数据和秘密不进入 Git。 |

另修复一个实际元数据问题：Cargo.lock 版本提取以前依赖 LF 字符串，在 CRLF 文件上漏报依赖版本；现按行匹配。原 Cargo.lock 原始字节及校验和不变。没有修改 group、sigma、shamir、ballot、verify、net、transcript、合约或依赖清单；没有改协议、证明语句、编码或安全假设。TCP 路径保留 dataflow，明确拒绝将 reference 比较冒充分布式运行。

## 4. Verification results

正式批次先在上述干净提交上运行：

```powershell
cargo fmt --check
cargo build --release --locked
cargo test --release --locked
```

全部通过：24 个单元测试、2 个集成测试，0 失败。正式批次日志中单元测试耗时 8.39 s，集成测试 33.81 s；这些测试耗时不是性能样本。Windows PowerShell 5.1 的完整 reproduction 流程已实际运行，前期小型冒烟批次也成功；后者明确排除。

新增测试覆盖四规模的 reference/dataflow 深度、完整门覆盖、加密输入依赖、reference 门内前驱和树层屏障、同层多 adder 实际成批派发。相同加密测试电路在阈值两侧均得到正确决策，并由公开 Engine 重放。两种策略均拒绝修改签名消息、重新签名但证明失效的消息、损坏的 transcript 文件和错误决策 claim。现有 TCP/隔离导出/断连/字节计数回归继续通过。

正式的 10 对、20 次加密计票全部满足 `Chain ∧ Snapshot ∧ Backend ∧ Binding ∧ Hash ∧ Bit ∧ Claim`。每次独立 verifier 是单独进程，仅接收 `public/` 路径；它重新验证 Groth16 入场、签名、子群、CGY 与部分解密证明、输入绑定、完整 transcript 哈希和决策 claim。计票本身也使用 `eng.process(&m, true)`，没有关闭验证。这些测试只建立所测实现行为的证据，不证明或扩展安全定理。oracle 在公开验证完成后运行；20/20 一致。配对前的 setup/ledger SHA-256、参数、选票证明、门数和决策逐对相同。

既有仅公开文件回放测试及本批次独立副本回放通过。冻结后重新计算全部公开文件 SHA-256，与 manifest 一致。没有失败运行进入下述统计。

## 5. Benchmark environment

- CPU：Intel(R) Core(TM) i7-14650HX，16 个物理核心、24 个逻辑处理器。
- 内存：检测为 31.8 GiB。
- OS：Microsoft Windows 11 专业版 10.0.26200 build 26200；架构 x86_64，MSVC release。
- Rust：`rustc 1.98.1 (48a229cea 2026-09-01)`；Cargo：`cargo 1.98.1 (797e8a9bc 2026-08-05)`。
- PowerShell：`5.1.26100.9818`；所有模式 `RAYON_NUM_THREADS=24`。
- 活动电源方案：`电源方案 GUID: 31a5c92e-ffe3-4740-a117-1ce4e7b05599  (FC Benchmark Max Performance)`；本任务只记录，未调整。
- Cargo.lock SHA-256：`ad1182690831da538c71fcd23e50e6afdf691d5c2ea6adb9015060f3357d864a`。
- 正式开始/完成（UTC）：`2026-11-22T12:42:15.4144635+00:00` / `2026-11-22T13:08:23.3627629+00:00`。
- 单一 Windows 机器、单进程内五个 trustee 角色和一个完整验证副本；不是五台机器、TCP/WAN 或云端比较。无人工 RTT、sleep 或计算延迟。

每次配对前重新生成真实 Groth16 选票并完成入场。n=8 使用公开示例权重及阈值 100；其他规模权重随机取 1..255，阈值为权重和的一半向下取整。不同重复可有不同选举实例，但每对内完全相同。所有选票关系保持 42,230 个 R1CS 约束、37 个公开输入。输入哈希、各次阈值及实际执行顺序见公开索引。

顺序为：n=8：R→D、D→R、R→D；n=64：D→R、R→D、D→R；n=256：R→D、D→R、R→D；n=1024：D→R。共五对 R 先执行、五对 D 先执行。没有同时运行另一套基准或编译任务。没有设置 CPU affinity、锁定实际频率或主动控制温度；顺序交替降低顺序偏差，不能消除 OS、频率和热状态波动。

**计时定义**（`src/experiment.rs:139–199`）：读取 setup/密钥、重放入场 ledger、构造共同 Circuit 和创建 transcript header 在计时前。起点在 trustee/RNG 初始化、公开预计算、Engine 加密 DAG 初始化及策略选择之前。`seconds_initialization` 是 gate 阶段的子集。`seconds_gates` 截止最后条件门完成且其消息写入；`seconds_release` 截止决策重构；`seconds_finalize_transcript` 覆盖末尾 flush/digest；`seconds_tally` 为三者之和。setup、选票 proving、入场、claim 发布、独立公开验证与 oracle 均排除在调度比较之外。公开验证表中使用 verifier 内部 `seconds_total`；另保留包括进程启动的 `seconds_process_wall` 于索引。所有时间均为实际墙钟测量。测试 setup/CRS 由原有 test-only dealer 生成；本批次入场使用本地事件账本模拟路径，谓词中的 Chain 是该账本的入场重放，不能当成新的 Arbitrum 实验。

## 6. Performance results

下表为总加密计票时间中位数 [最小值, 最大值]，单位秒。前三规模各策略 3 次，n=1024 每策略仅 1 次；最后一行只代表单次观察。S、R 用未舍入的各策略中位数计算。

| Voters | Gates | Reps/mode | Reference time (s) | Dataflow time (s) | Speedup S | Runtime reduction R |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 134 | 3 | 2.329 [2.297, 2.330] | 1.164 [1.157, 1.179] | 2.001× | 50.02% |
| 64 | 1,086 | 3 | 6.968 [6.836, 7.081] | 4.894 [4.891, 4.922] | 1.424× | 29.76% |
| 256 | 4,350 | 3 | 19.948 [19.889, 19.971] | 17.146 [17.103, 17.220] | 1.163× | 14.05% |
| 1024 | 17,406 | 1 | 69.439 [69.439, 69.439] | 65.567 [65.567, 65.567] | 1.059× | 5.58% |

阶段中位数如下（秒）；gate 包括初始化，不能再加一次 initialization。各阶段中位数的和不必等于总时间中位数。

| n | Mode | Initialization (subset) | Gates incl. init | Terminal release | Finalize transcript | Total tally | Public verify |
|---:|---|---:|---:|---:|---:|---:|---:|
| 8 | reference | 0.080218 | 2.317316 | 0.011127 | 0.000260 | 2.328730 | 1.234692 |
| 8 | dataflow | 0.080514 | 1.153015 | 0.010943 | 0.000248 | 1.163858 | 0.632790 |
| 64 | reference | 0.080953 | 6.956601 | 0.011036 | 0.000292 | 6.968056 | 3.425343 |
| 64 | dataflow | 0.083825 | 4.882824 | 0.011241 | 0.000257 | 4.894318 | 1.800180 |
| 256 | reference | 0.088752 | 19.937184 | 0.010804 | 0.000282 | 19.948275 | 10.813941 |
| 256 | dataflow | 0.088446 | 17.134989 | 0.011021 | 0.000283 | 17.146169 | 8.667640 |
| 1024 | reference | 0.105123 | 69.427765 | 0.011193 | 0.000286 | 69.439244 | 46.671289 |
| 1024 | dataflow | 0.110683 | 65.555592 | 0.010829 | 0.000282 | 65.566703 | 44.167980 |

完整原始时间如下，按每对的真实执行顺序排列，单位秒。原始双精度值与额外字段在 `evidence/schedulers.json`，没有修改原始 manifest。

| n | Rep | Order | Mode | Gate phase | Release | Finalize | Total tally | Public verify | Decision |
|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|
| 8 | 0 | 1 | reference | 2.285417 | 0.011127 | 0.000260 | 2.296803 | 1.234692 | 0 |
| 8 | 0 | 2 | dataflow | 1.145820 | 0.011045 | 0.000235 | 1.157100 | 0.600722 | 0 |
| 8 | 1 | 1 | dataflow | 1.167943 | 0.010943 | 0.000316 | 1.179202 | 0.632790 | 1 |
| 8 | 1 | 2 | reference | 2.318797 | 0.010846 | 0.000289 | 2.329932 | 1.251506 | 1 |
| 8 | 2 | 1 | reference | 2.317316 | 0.011217 | 0.000197 | 2.328730 | 1.232552 | 1 |
| 8 | 2 | 2 | dataflow | 1.153015 | 0.010594 | 0.000248 | 1.163858 | 0.636678 | 1 |
| 64 | 0 | 1 | dataflow | 4.882824 | 0.011241 | 0.000253 | 4.894318 | 1.856753 | 0 |
| 64 | 0 | 2 | reference | 7.069404 | 0.011036 | 0.000295 | 7.080735 | 3.425343 | 0 |
| 64 | 1 | 1 | reference | 6.956601 | 0.011186 | 0.000269 | 6.968056 | 3.495835 | 1 |
| 64 | 1 | 2 | dataflow | 4.910881 | 0.011327 | 0.000259 | 4.922466 | 1.800180 | 1 |
| 64 | 2 | 1 | dataflow | 4.879432 | 0.010919 | 0.000257 | 4.890608 | 1.776929 | 1 |
| 64 | 2 | 2 | reference | 6.824433 | 0.010880 | 0.000292 | 6.835605 | 3.392453 | 1 |
| 256 | 0 | 1 | reference | 19.937184 | 0.010804 | 0.000287 | 19.948275 | 11.076998 | 0 |
| 256 | 0 | 2 | dataflow | 17.208928 | 0.011138 | 0.000259 | 17.220326 | 8.593993 | 0 |
| 256 | 1 | 1 | dataflow | 17.134989 | 0.010872 | 0.000307 | 17.146169 | 8.750968 | 0 |
| 256 | 1 | 2 | reference | 19.877858 | 0.010728 | 0.000271 | 19.888857 | 10.696598 | 0 |
| 256 | 2 | 1 | reference | 19.959072 | 0.011215 | 0.000282 | 19.970568 | 10.813941 | 0 |
| 256 | 2 | 2 | dataflow | 17.091590 | 0.011021 | 0.000283 | 17.102893 | 8.667640 | 0 |
| 1024 | 0 | 1 | dataflow | 65.555592 | 0.010829 | 0.000282 | 65.566703 | 44.167980 | 0 |
| 1024 | 0 | 2 | reference | 69.427765 | 0.011193 | 0.000286 | 69.439244 | 46.671289 | 0 |

选票 proving 与入场在每对中只执行一次，并由两模式共享。下表给出每规模这些排除项的中位数 [最小, 最大]，并非计票加速的一部分。

| n | Independent election instances | Ballot proving, all ballots (s) | Admission (s) |
|---:|---:|---:|---:|
| 8 | 3 | 3.688 [1.941, 3.873] | 0.016 [0.011, 0.023] |
| 64 | 3 | 29.979 [27.836, 30.293] | 0.075 [0.075, 0.085] |
| 256 | 3 | 118.402 [115.964, 119.160] | 0.269 [0.268, 0.281] |
| 1024 | 1 | 467.377 [467.377, 467.377] | 1.070 [1.070, 1.070] |

## 7. Speedup and percentage improvement

`S = median(T_reference) / median(T_dataflow)`；`R = 100 × (median(T_reference) − median(T_dataflow)) / median(T_reference)`。不对每对 speedup 取中位数，不使用深度比例代替时间比例。

n=8：S=2.001×、R=50.02%；n=64：S=1.424×、R=29.76%；n=256：S=1.163×、R=14.05%；n=1024：S=1.059×、R=5.58%。

这组观测中 dataflow 在四规模均更快。理论深度缩减比例随规模增加，但墙钟加速不随之等比例增加。规模增大后，两策略都有更宽的独立门批次，且共同承担相同门数的椭圆曲线和证明工作，因此固定核心数下可利用并行度逐渐饱和。此解释符合源码与批次统计，不是每种开销的独立消融结论。n=1024 只有一对，不能据此估计方差、置信区间或普遍性能保证。

**历史测量不可混算。** T002 的 `paper-data.json` 及其引用的原始 n=1024 manifest 记录 dataflow 28.318663 s、24 个 Rayon 线程；本批次为 65.566703 s。新的初始化计时只有 0.110683 s，不能解释此差异。源码检查确认两者都启用完整计票验证；旧记录没有足够的频率、温度与 OS 调度状态来确定剩余原因。本任务没有定位这一跨批次差异，也没有重跑挑选较快数值。它不影响本批次相同源码和输入下的配对结果，但不能将旧 dataflow 时间配上新 reference 时间。论文若同时保留历史表，应明确标注独立批次；不能声称两表绝对时间相同或把差异直接归为某项实现改进。

## 8. Scheduling analysis

静态策略深度已由实际运行的策略和测试验证，公式及 DAG 计算得到：

| Voters | Gates | Reference depth | Dataflow depth | Depth reduction | Reference max layer width | Dataflow max layer width |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 134 | 72 | 25 | 65.3% | 4 | 32 |
| 64 | 1086 | 147 | 37 | 74.8% | 32 | 256 |
| 256 | 4350 | 207 | 45 | 78.3% | 128 | 1024 |
| 1024 | 17406 | 275 | 53 | 80.7% | 512 | 4096 |

深度是条件门调度的关键路径层数，不等于每门的多阶段密码协议轮数、signed message 数或网络 RTT。实测首 masking 批次数恰好与深度相同，这是一项另外记录的运行时观测。最大批次只统计 trustee 0 的新 gate masking 项；不冒充所有协议项的最大消息长度。树层 barrier 数包含从最后聚合层进入减法器的边界，不含终端密码协议本身的依赖。

下表的通信/批次计数在同规模的所有重复中一致。字节为整个序列化 transcript 文件的精确长度，含 70 字节 header、长度前缀和签名；不是 TCP wire bytes、流量费用或多机总发送量。本任务没有网络通信测量。

| n | Mode | Gate batches | Max new gates/batch | Tree-stage barriers | Signed messages | Protocol items | Transcript bytes |
|---:|---|---:|---:|---:|---:|---:|---:|
| 8 | reference | 72 | 4 | 3 | 1,095 | 2,025 | 734,465 |
| 8 | dataflow | 25 | 32 | 0 | 390 | 2,025 | 663,260 |
| 64 | reference | 147 | 32 | 6 | 2,220 | 16,305 | 5,265,370 |
| 64 | dataflow | 37 | 256 | 0 | 570 | 16,305 | 5,098,720 |
| 256 | reference | 207 | 128 | 8 | 3,120 | 65,265 | 20,501,230 |
| 256 | dataflow | 45 | 1,024 | 0 | 690 | 65,265 | 20,255,800 |
| 1024 | reference | 275 | 512 | 10 | 4,140 | 261,105 | 81,184,090 |
| 1024 | dataflow | 53 | 4,096 | 0 | 810 | 261,105 | 80,847,760 |

每门每 trustee 仍产生 masking、rerandomization reveal、partial-decryption 三项，释放也有三项；总项数为 `15 × (gates + 1)`。dataflow 将更多同时就绪的门装入同一认证消息，减少签名/验证、消息封装、调度扫描及小批量线程池工作。重复中 transcript 长度固定，因为编码和证明长度固定，并不表示重复使用了随机性或证明。两策略的 transcript 字节差恰为消息数差的 101 倍，与本编码的批次/消息固定开销一致。原语工作量不变；门的并行粒度和消息边界共同变化，不能将全部速度改善单独归因于网络或单一线程池因素。

## 9. Related-work context

下列数值仅来自原始论文或作者版本，功能、泄露目标、硬件和测量边界不同，不能与本任务计算跨系统 speedup。

| Work / primary source | Function and disclosure | Experiment size / hardware | Verified reported measurement and scope |
|---|---|---|---|
| [CGY, *A toolbox for verifiable tally-hiding e-voting systems*](https://inria.hal.science/hal-03367930v2/document), §3.3, Table 3；作者版本正文 pp.12–13（HAL PDF pp.13–14），ESORICS 2022, DOI [10.1007/978-3-031-17146-8_31](https://doi.org/10.1007/978-3-031-17146-8_31) | Condorcet–Schulze，全 tally hiding；不是本任务的二元加权阈值电路。 | 3 trustees、无 threshold，每方 4 计算线程；同一双 16-core AMD EPYC 7282 / 128 GB 服务器，真实 loopback 网络调用，C++/libsodium。 | 5 candidates：64 voters 为 1 min 50 s / 49 MB；1024 voters 为 15 min / 595 MB。选票验证在 MPC 外，不据此推导本系统加速。 |
| [Ordinos, author extended technical report](https://www.sec.uni-stuttgart.de/documents/publications/kuestersliedtkemuellerrauschvogt-ordinos-tr-2019.pdf), §8, PDF pp.24–27 | Fully tally-hiding 的加密排名与结果函数，Python/gmpy2、2048-bit Paillier。 | LAN 每 trustee 一台 i5-7500T 2.70 GHz / 16 GB ESPRIMO；另测同机与异地 VPN。 | 40 candidates、3 trustees、16-bit counts，第二阶段 top-position set 函数约 6.33 min；不含构造加密排名的第一阶段。离线材料也不在该计票基准内。候选数与计数位宽是核心尺度，不能将 voters 与本电路门数对应。 |
| [Kryvos, CCS 2022 author paper](https://publ.sec.uni-stuttgart.de/huberkuesterskripsliedtkemuellerrauschreisert-ccs-2022.pdf), §4 / §4.2, printed pp.1449–1450, Fig.1；DOI [10.1145/3548606.3560701](https://doi.org/10.1145/3548606.3560701) | 多类投票规则，Groth16 证明结果；publicly tally-hiding，talliers 可知完整聚合 tally。 | Ubuntu 20.04、16 GB、8-core machine，基准仅用 1 core；§4 未给 CPU 型号。 | 多数结果函数在 1000 choices 约 100 s，主要是最终 tallying SNARK；完整六等级 Majority Judgement 是例外。choices 不是 voters。原文索引可核对上述段落；本机直接 PDF 下载 TLS/超时失败，未声称有本地 PDF 哈希。 |
| [Kite, arXiv:2501.05626v1](https://arxiv.org/html/2501.05626v1), §6.1–6.2 | DAO 私密委托/撤销/重委托；不是本任务的加密 winner-only 计票计算。 | consumer-grade laptop，精确 CPU/RAM 未在该版实验段给出；10 次平均；匿名集合最高 25。 | delegation 7–167 s 随匿名集合变化；gas 使用本地 Anvil。该值是委托证明/操作指标，不是全选举加密计票耗时，也不是实际 testnet gas 证据。 |

本任务的核心证据是同一代码、同一负载、同一机器内的控制比较。上述文献只提供任务和测量方法的语境。CGY、Ordinos、Kite 的可访问原始 PDF/提取文本仅保存在本地忽略的研究 work 目录；没有将其复制进公开源码库。

## 10. Paper-ready material

以下英文材料及 LaTeX 表可直接提供给论文作者；本任务没有修改 manuscript。建议放在 evaluation 内，现有 CGY 文献引用沿用原稿键值，不虚构 BibTeX 键。

**Proposed subsection title: Controlled Comparison of Scheduling Policies**

We compare level-serial reference scheduling with dataflow scheduling on the same encrypted weighted-threshold circuit. Both policies use identical admitted ballots, weights, threshold, committee keys, gate protocols, and release semantics within each pair. The reference policy runs independent ripple adders concurrently within a tree level, preserves each adder's gate order, and inserts barriers between tree levels. Dataflow scheduling dispatches every gate whose encrypted inputs are available. Both policies use the same CGY conditional-gate implementation \cite{toolbox}.

We ran the release build on a Windows 11 workstation with an Intel Core i7-14650HX, 31.8 GiB RAM, and 24 Rayon threads. We alternated policy order across paired elections. Each policy was measured three times for n=8, 64, and 256, and once for n=1024. Tally timing includes initialization, proof generation and checking, signatures, encrypted arithmetic, and transcript finalization. It excludes setup, ballot proving, admission, claim publication, and independent replay. Every measured transcript passed independent public verification and agreed with the isolated plaintext oracle.

Table \ref{tab:schedulers} reports measured tally runtimes. The observed reference-to-dataflow runtime ratio ranged from 1.06 to 2.00. Reference gate depths were 72, 147, 207, and 275; dataflow depths were 25, 37, 45, and 53. These structural reductions differ from elapsed-time reductions. Wider ready-gate batches also reduce signed-message overhead. At larger scales, both policies offer substantial parallel work, which limits the additional benefit on a fixed thread budget. The n=1024 comparison is a single-run observation. Its absolute runtime differs from the earlier evaluation batch, and the cause remains unresolved. This experiment measures scheduling and batching effects within our implementation; it does not establish an end-to-end election speedup or a speedup over the CGY authors' software.

```latex
\begin{table}[t]
\centering
\caption{Same-circuit scheduler comparison on an Intel Core i7-14650HX
(24 threads, 31.8 GiB RAM, Windows 11). Times are median encrypted-tally
wall-clock seconds; brackets give the observed minimum and maximum.
Each policy has three repetitions except $n=1024$, which has one.
All transcripts passed independent verification and oracle comparison.
Setup, ballot proving, admission and public replay are excluded.}
\label{tab:schedulers}
\setlength{\tabcolsep}{3pt}
\begin{tabular}{rrrrrr}
\hline
$n$ & Gates & Reference (s) & Dataflow (s) & Speedup & Reduction \\
\hline
8 & 134 & 2.33 [2.30,2.33] & 1.16 [1.16,1.18] & $2.00\times$ & 50.0\% \\
64 & 1086 & 6.97 [6.84,7.08] & 4.89 [4.89,4.92] & $1.42\times$ & 29.8\% \\
256 & 4350 & 19.95 [19.89,19.97] & 17.15 [17.10,17.22] & $1.16\times$ & 14.0\% \\
1024 & 17406 & 69.44 & 65.57 & $1.06\times$ & 5.6\% \\
\hline
\end{tabular}
\end{table}
```

文献引用：CGY 的作者、标题、年份、DOI 见第 9 节。该表和新测量本身引用本 artifact 的源码提交与测量索引即可。已核对原稿 `paper/PaperTex/main.tex` 使用 `toolbox` 引用键；上文保留该键。

## 11. Reproduction

在 Windows PowerShell 5.1 / MSVC Rust 环境、仓库根目录执行：

```powershell
git checkout c6804f3ef6ae6eaf7d33f5741745885cbf1fedfb
$env:PATH = "$env:USERPROFILE\.cargo\bin;" + $env:PATH
cargo fmt --check
cargo build --release --locked
cargo test --release --locked
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\reproduce.ps1 -SchedulerComparison -SchedulerThreads 24
```

脚本会重做检查、生成全新的 `results/local/<timestamp>-<source-revision>/`，运行指定的 3/3/3/1 配对方案。默认路径拒绝碰撞；同一输入复制到两个独立变体目录，秘密在各自 `private/`，证明中间文件在 `work/`。新随机选举的哈希和结果可以不同，不应期待逐字节重复本批次 transcript。不要在已有实验目录直接再运行 tally/verify；verifier 会写 verify.json，回放需先复制到新的仅公开目录。

可单独选择策略：

```powershell
.\target\release\wod.exe tally --dir <fresh-prepared-election> --scheduler reference
.\target\release\wod.exe tally --dir <another-fresh-prepared-election> --scheduler dataflow
```

上述两个目录必须从同一封存 setup/board 复制，且没有现存 transcript；完整配对应优先使用唯一的 reproduce.ps1 入口。

正式原始数据目录（保留在作者机器，不进入 Git）：

`D:\31831\Desktop\Voting\results\local\20261122-204215-407-c6804f3e`

其相对路径为 `results/local/20261122-204215-407-c6804f3e/`。`exp1/exp2/exp3/exp4` 分别对应 n=8/64/256/1024；运行 manifest 在 `expK/nN/repR/local-<scheduler>/public/manifest.json`。批次日志在 `logs/`；独立副本 replay 在独立 scheduler-audit 目录的 `work/public-replay/reference/public/` 和 `work/public-replay/dataflow/public/`。审计/文献工作材料另保存在同一 `results/local/` 下的 `20261122-203414-6bfe47b-scheduler-audit/` 目录，不纳入性能统计。生成数据从开发 clone 转存至上述 D 盘目录时逐文件核验字节与哈希；原始记录内的执行目录字符串保留原值，未为迁移重写 manifest。

公开的小型索引为 [evidence/schedulers.json](../evidence/schedulers.json)，包含全部 20 条未舍入时间、调度统计、阈值、配对输入哈希、每个公开文件哈希、验证结果和机器信息。没有 trustee share、签名种子、voter secret、vote、oracle tally 或私密输入。审计检查了公开文件 allowlist（setup/ledger/transcript/claim/verify/manifest）及对应序列化类型；这些类型只含公共参数、密文、证明、签名和公开决策。公开权重不是秘密票值。完整原始运行还含 private/work，不能整目录发布。

| File | SHA-256 |
|---|---|
| Batch `manifest.json` | `7f8fe468fca8d9539333e45731121b7c6734e1d76e8c3d3130ff00b38f866f4d` |
| Batch `comparison.json` | `b050171df9f9c1a626a442650c42c74882516dc9c40e7494ce55d7e3a5c6b26d` |
| Published `evidence/schedulers.json` | `ca817c6a0acbb736f1e5f3d604360d98cf4699824d955356fe607bd3d697db11` |
| Cargo.lock | `ad1182690831da538c71fcd23e50e6afdf691d5c2ea6adb9015060f3357d864a` |
| Measured release wod.exe | `25a857fd817a462956e4f211387036ea5f2f93474dcd9248f99e54c93b14cc43` |

批次根 manifest 的 `public_artifacts` 记录 140 个公开文件的完整 SHA-256，全部重新计算匹配；每次运行 manifest 另列其 setup/ledger/transcript/claim/verify 的原始哈希。下列哈希固定了 20 个原始运行 manifest；它们又固定对应公共证据。

| n | Rep | Scheduler | Original manifest SHA-256 |
|---:|---:|---|---|
| 8 | 0 | reference | `84b280774250f6c64feddd9a19ab267faa5405aa4e40b610f43b10fa01008908` |
| 8 | 0 | dataflow | `348dff8fed9bb2ad008d1d504875be9e4aa1aa8a45634314157af9bdada23c6c` |
| 8 | 1 | dataflow | `231a99f6ed23e9f1e77ab08935f02891fdaf2a9b97036f894e1be94af693d6f8` |
| 8 | 1 | reference | `de5f6e89af9fc3ce1d4ef83df2ea74f282d8f82c38400de5db2f6e01590aa8c7` |
| 8 | 2 | reference | `3a8a0fa2d7e653de8c1cf8fa628d237499ee83d61bde58952dff7dbcf897d9ee` |
| 8 | 2 | dataflow | `add48318406f16a51b8cdea64289337eb27b2c01a443b4210c9a9569bb26201a` |
| 64 | 0 | dataflow | `23b0ebf415e0afa11ccace7ffcdb2edf00c1df82e9933cda28924679eefa627c` |
| 64 | 0 | reference | `6ab7ab6a2bb57a79f514aaf0cb1eb0e0a2d65d714067c39f67d1fb02ea63ca0e` |
| 64 | 1 | reference | `b1e76613743a5537769139a4d1d68855f5cf1465f682c4c7a671d2208f3ddbbb` |
| 64 | 1 | dataflow | `8f47eb9d294d093dab51d7f9f9cbccac7bbab47bd5b6d5455704f91b7cd8f6fd` |
| 64 | 2 | dataflow | `ff02137a237c6b8f0ef02d040f70ada808bd87218521243439592f3aa594a090` |
| 64 | 2 | reference | `a40316f6284e031659d60dd3d207d6e7ca32bfb25dc9240d40a1e70ecfa2c6a1` |
| 256 | 0 | reference | `dd281fd9deb962ddc4702d49c0e322b6f820df29927fa06319f6bc9ccc10f39c` |
| 256 | 0 | dataflow | `950a8abab5d110954f3f3841e0127c29b1433bac092c19471faa21b93ebff26b` |
| 256 | 1 | dataflow | `ff0f8f49e77080b151db9eb267c1aa8b1c61d2705f7df48a70502ca4e0478245` |
| 256 | 1 | reference | `171aab0b94a708f9292d9e42d59db207759b9007166f974454a059ac311d0db4` |
| 256 | 2 | reference | `62b5cf22d2ce50ef4659ca8acc7a4865a5b08728a1e7e7bc3de4afe515bcab1f` |
| 256 | 2 | dataflow | `396367a79f09da54590927af0fc9805fc2f3ae48d113014f274aec26c65bf468` |
| 1024 | 0 | dataflow | `952446cbb49ed4d9540d11371485284fe48ae463ac4336080439be3dbf67b0a2` |
| 1024 | 0 | reference | `3dd67e640674d1880a374f7da53ff13ec3937029cd513b553f46e515ea0b871c` |

新公开索引可使用 `Get-FileHash .\evidence\schedulers.json -Algorithm SHA256` 检查。原始 manifest 和以往研究数据均未就地重写。源码提交完整保留 v0.2.0 为祖先；本任务不移动既有 tag，不广播交易、不调用云端部署、不产生新的云资源费用。

## 12. Final assessment

**SUITABLE_FOR_MANUSCRIPT_INCLUSION**。四规模控制比较、规定的 20 次真实密码计票、统一计时、公开验证、oracle 比对、配对输入一致性和公开哈希审计均完成，没有实验或验证失败阻碍这项基线进入论文。第 7 节披露的历史 n=1024 跨批次时间差仍未定位，论文整合须保留这一限制。所有门和安全检查保留。历史两份公开证据包重新计算的 SHA-256 仍分别为 `9212d58464c0c149e945016776781ba0eb2c0b80f99b74dbb701fcf85be8fd62`（T003 多机/执行）和 `dcde886e8e7b4d0c90a61380318040b0eb24cbfa9befa37c6a06bc1d7ca163d4`（先前本机/入场证据），与原记录一致。

论文应引用实际总加密计票中位数及原始范围，保留单进程范围、消息批处理效应和 n=1024 单次观测限制。不能将此结果写为 CGY 原始软件的直接改进、真实 WAN 改进或包括 setup/proving/链上操作的全协议加速。本任务没有更新论文或生成新 PDF；作者可依据第 10 节整合到最终稿。历史本机、多机及链上数据的来源和计时边界不同，没有混入本表。

提交范围限于已验证的调度源码、针对性测试、原 reproduction 入口、README、本报告和小型公开索引；秘密、大型 transcript、历史报告和 manuscript 不进入新提交。未移动或删除历史 tracked 文件，未增加 workspace、依赖、协议实现或云端基础设施。
