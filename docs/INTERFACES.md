# SecLoop — 子系统接口契约（冻结版 v1）

> **本文件是 SecLoop 四个子系统的接口契约。** 跨子系统的数据结构、HTTP 端点、字段名与极性语义都以本文件为准；标注"必须"/"禁止"的条目是 normative 的，实现与 `tests/**` 的契约测试都不得偏离。
> 契约变更**先改本文件**，再改实现；四个子系统（靶机与 IDS、SOC 与编排、策略生成与工具、训练）都按本文件校验。
> 论文依据：IEEE JSAC vol.44 (2026), DOI `10.1109/JSAC.2025.3643844`，系统 SecLoop + 算法 SA-GRPO。

---

## 0. 全局约定

| 项 | 约定 |
|---|---|
| Python | 3.11（与论文时期一致） |
| 许可证 | Apache-2.0（文件头统一写 `# SPDX-License-Identifier: Apache-2.0`） |
| 日志 | `logging` 标准库；**禁止** `print` 调试残留 |
| 编码 | 所有文件 UTF-8，LF 换行 |
| 禁止 | 任何硬编码 API key / 云厂商名 / 内网端点；`trl` **不 vendor**，走依赖 |
| 禁止 | 任何"编造日志"式的假数据路径——所有告警必须来自真实 Suricata |
| 时间 | 时间戳统一 ISO-8601 本地时区字符串 |

---

## 1. 实验环境常量

| 常量 | 值 |
|---|---|
| 红队机名 | `kali` |
| 蓝队机名 | `target` |
| 红队 IP | `192.168.57.199` |
| 蓝队 IP | `192.168.57.200` |
| 网络 | `192.168.57.0/24`，`private_network` |
| Provider | `vmware_desktop` |
| Box：红队 | `kalilinux/rolling` |
| Box：蓝队 | `bento/ubuntu-18.04` |
| 快照名 | `kali_init`、`target_init`（由 **host 侧** `vagrant/snapshots.sh` 创建；`up.sh` 会自动调用它。**guest provisioner 无法创建** —— VMware 快照是 host 操作，`target_setup.sh` 末尾只能打印提示） |
| 攻击模式 | **仅** `sqli` |
| 靶机探活 URL | `http://192.168.57.200/index.php` |
| 靶机漏洞点 | `http://192.168.57.200/search.php?id=<id>` |
| SOC 服务端口 | `8988` |
| SOC 端点 | `http://127.0.0.1:8988/execute_ability` |
| 内存 / vCPU：红队 | `2048` MB / `2`（`vagrant/Vagrantfile` 与 `battlefield/soc/iac_generator.py` 的默认值必须一致） |
| 内存 / vCPU：蓝队 | `4096` MB / `2`（同上） |

> `kali` 为滚动发行版：攻击脚本**只能依赖 Python 3 标准库 + `requests`**，其余依赖必须由 `vagrant/provision/attacker_setup.sh` 显式安装。

### 1.1 为什么网段是 `192.168.57.0/24` 而不是 `192.168.56.0/24`（**不要改动**）

在 `192.168.56.0/24` 上创建 host-only 网络会被 VMware 拒绝并报错：

```
The host only network with the IP '192.168.56.199' would collide with
another device '以太网 4'. ... Please choose another IP or shut down the
existing device.
```

原因是 **`192.168.56.0/24` 恰好是 VirtualBox host-only 适配器的默认网段**
（`VirtualBox Host-Only Ethernet Adapter` = `192.168.56.1/24`）。VMware 无法在
同一网段上再建一个 host-only vmnet。

这不是个别机器的偶发问题：**只要用户同时装了 VirtualBox 和 VMware（Vagrant
用户的常见组合），`192.168.56.0/24` 必然冲突。** 因此本仓库把网段固定在
**`192.168.57.0/24`**——紧邻但在本机与常见默认配置中均未被占用。

改动此网段时必须**同步**以下位置（否则 SOC 会连不上靶机）：
`docs/INTERFACES.md` §1、`vagrant/Vagrantfile`、`battlefield/soc/iac_generator.py`、
`battlefield/soc/service_probe.py`、`battlefield/attacks/sqli_lab.py`（安全白名单
`ALLOWED_TARGET_NETS`）、`battlefield/soc/attack_commands.json`、`agent/config.json`、
`target/webapp/db.env`、`target/suricata/local.rules` 以及 `tests/**` 与 fixture。

---

## 2. 攻击结果契约（RTC ⇄ 攻击脚本）

### 2.1 契约形式：单行 JSON，前缀标记

攻击脚本**必须**在 stdout 打印**恰好一行**机器可解析的结果：

```
[RESULT] {"attack_mode":"sqli","target_ip":"192.168.57.200","score":0.4,"stages":[{"name":"db_name_length","success":true,"weight":0.1}, ...],"error":null,"abort_kind":null}
```

**字段顺序固定**（消费者与生产者两侧都有测试锁死）：`attack_mode`、`target_ip`、
`target_port`、`target_url`、`mode`、`delay_s`、`score`、`stages`、`extracted`、
`oracle_errors`、`requests`、`elapsed_s`、`error`、`abort_kind`。

规则：
- 前缀严格为 `[RESULT] `（含一个空格），其后必须是**合法 JSON 单行**。
- `stages` 顺序固定、`weight` 之和为 `1.0`；`score = Σ(weight × success)`。
- ⚠️ **这个加权 `score` 与 PEV 的 `rs_attack` 不是同一个量，不可互相替代。**
  论文 Eq.11 的 `rs_attack` 是**无权**平均 `(1/m)·Σ(stage.success)`，**完全不使用 `weight`**。
  例：5 段中只有权重 0.1、0.1 两段成功时，`score = 0.2` 而 `rs_attack = 0.4`。
  `score` 是攻击脚本的自报结果（供日志与人工核对），`rs_attack` 才参与 Eq.13 与奖励。
- 若脚本崩溃/超时，仍应尽量打印 `[RESULT]` 且 `error` 非空、`stages` 全 `false`、`score = 0.0`，
  **并且必须自报 `abort_kind`**（下一节）。
- 允许在 `[RESULT]` 之前打印任何**人类可读**日志；解析方只认 `[RESULT]` 行。

#### `abort_kind`：生产者自报"为什么停了"

**问题**：一次致命中止与一次完美防御在线上是**同一种字节**——一条合法 `[RESULT]` 行，
每一段都是 `false`。消费者无法区分"防御把我挡住了"与"我们自己的脚手架坏了"，于是
**两者都被记了满分**（`round_defended.json` 正是这种情形：
在健康锚点就超时中止、`requests: 0`，却被当成完美防御，`rs_attack = 0.0`、`rs_service = 1`
⇒ `R_eva = 1.0`）。

**做法**：生产者用机器可读字段自报中止原因，消费者**按字段判定**，不靠猜。

| `abort_kind` | 含义 | 消费者如何处理 |
|---|---|---|
| `null` | 跑完了（无论成功多少段） | 正常测量 |
| `target-unreachable` | **攻击机到不了靶机**：连接/超时失败、健康锚点非 `200`、或 `200` 但没有契约标记 | **算被挡住**：`rs_attack` 取上报阶段（全 `false` ⇒ `0.0`），并置 `attack_unreached = True` |
| `oracle-unconfirmed` | 靶机可达，但 SQLi 时间盲注预言机建立不起来（标定失败） | **无结论**：本轮未测量，不给分 |
| `dependency-missing` | 探针自身的前置缺失（攻击机上没有 `requests`） | **无结论**：未测量 |
| `config-invalid` | 调用本身非法（目标不在实验网段内） | **无结论**：未测量 |
| `unclassified` | 其它一切情况（**默认值**） | **无结论**：未测量 |

两条硬性规定：

1. **默认必须是 `unclassified`，绝不能是"挡得住"。** 一条忘记加分类的 `raise` 会退化成
   "我们不知道"，而不会退化成"防御有效"。`tests/lab/test_abort_kind_contract.py` 用 AST
   断言 `check_health()` 的每一处 `raise` 都带 `target-unreachable`、`calibrate()` 的每一处
   都带 `oracle-unconfirmed`，所以新增 `raise` 想漏也漏不掉。
2. **常量在两处定义，测试锁死一致。** 攻击脚本跑在攻击机上、必须自包含（不能 `import`
   SOC 包），所以词表复制了一份；**权威副本在 `battlefield/soc/policy_execution_validator.py`**
   （`ABORT_KINDS`、`TARGET_UNREACHABLE`），因为消费方才是解释字段的一方。一致性由测试保证。

**"攻击没跑"到底算不算"被挡住"——算。** 健康锚点连接失败正是 `DROP` 规则
在攻击机侧的样子，所以 `target-unreachable` 给分。但**因果**不由 `abort_kind` 承担：

#### 前置对照：证明中止是防御造成的

`abort_kind = target-unreachable` 只说"到不了"，不说"是谁造成的"。靶机在部署之前就已经坏了
也会产生同样的字段。因此开启 `pre_attack_sample`（环境变量 `SOC_PRE_ATTACK_SAMPLE=1`，
见 §3.1）后，SOC 会**先**跑一次同样的攻击拿到基线，再部署策略、再跑一次，然后：

| 前置对照 | 后置 | `caused_by_defence` | 本轮判定 |
|---|---|---|---|
| 到得了靶机 | 到不了 | `True` | **已证明**是防御造成的，给分 |
| **也**到不了 | 到不了 | `False` | **环境故障**，不是防御：本轮**未测量**，不给分 |
| 没开 / 对照本身没测出来 | 到不了 | `None` | 算被挡住，但**标注为未证明** |

判定是纯函数 `resolve_causation()`（`battlefield/soc/execution_pipeline.py`），三种输入各自
可单测。`caused_by_defence` 出现在 RTC 结果里，`None` 表示"没人查过"，**不得**被写成 `True`。

> 未开启前置对照时，`attack_unreached = True` + `caused_by_defence = None` 的组合意味着：
> 这一轮**可以作为测量**，但**不能作为论文意义上的证据**去主张"该策略挡住了攻击"。


### 2.2 为什么用 JSON 而不是 `Score:` 文本

三套互不兼容的分数契约（`Score:\s+` / `score:` / `Total Score:`）会让攻击分恒为 0，而正则回退逻辑会把任意非空输出**编造成一个成功阶段**。JSON 契约从根上消除这两类问题。

### 2.3 SQLi 的 5 个分段（固定）

| # | `name` | 含义 | `weight` |
|---|---|---|---|
| 1 | `db_name_length` | 用时间盲注判定当前库名长度 | 0.1 |
| 2 | `db_name` | 二分搜索提取库名 | 0.1 |
| 3 | `table_name` | 提取首个表名 | 0.2 |
| 4 | `column_name` | 提取目标表的首个列名 | 0.2 |
| 5 | `dump_row` | 提取该列的一行值 | 0.4 |

**RTC 解析要求**：必须严格按 `[RESULT]` JSON 解析；**解析失败时 `rs_attack` 必须为 `0.0` 并记 WARNING**，绝不允许把非空 stdout 当成功。

---

## 3. SOC HTTP API（`battlefield/soc_server.py`）

### 3.1 `POST /execute_ability`

**请求体（规范形态，整条策略一次性提交）**

```json
{
  "strategy": [
    {"tool": "block_ip", "params": {"ip": "192.168.57.199"}},
    {"tool": "bash",     "params": {"command": "..."}}
  ],
  "attack_mode": "sqli",
  "red_vm": "kali",
  "blue_vm": "target"
}
```

**兼容形态（旧客户端，仅单条命令）**：`{"command": "<shell 命令>"}`，内部等价于单元素 `strategy`。

**响应体（HTTP 200）**

下面的例子刻意让 `score`（加权，`0.2`）与 `rs_attack`（无权，`0.4`）**不同**：5 段里 2 段
成功，加权和 `0.1+0.1=0.2`，无权平均 `2/5=0.4`。两者不可互换（§2.1）。

```json
{
  "success": true,
  "score": 0.2,
  "feedback": {
    "rs_exe": 1.0,
    "rs_attack": 0.4,
    "rs_service": 1,
    "F_i": 2.4,
    "defense_effectiveness": 0.6,
    "stages": [
      {"name": "db_name_length", "success": true,  "weight": 0.1},
      {"name": "table_name",     "success": true,  "weight": 0.1},
      {"name": "column_name",    "success": false, "weight": 0.2},
      {"name": "admin_row",      "success": false, "weight": 0.2},
      {"name": "data_exfil",     "success": false, "weight": 0.4}
    ],
    "tools": [
      {"tool": "block_ip", "success": true, "output": "...", "error": null}
    ],
    "service_probe": {
      "target_http": true,
      "attacker_reachable": true
    },
    "pre_attack_stages": [
      {"name": "db_name_length", "success": true, "weight": 0.1}
    ]
  },
  "attack_mode": "sqli",
  "elapsed_s": 42.7,
  "error": null
}
```

失败时 HTTP 200 + `"success": false` + `"error": "<原因>"`（不要用 5xx 表达业务失败，除非服务本身不可用）。**唯一例外是 `429`**：VM 池在等待窗口内拿不到空闲 VM 对时返回 `429` + `Retry-After` 语义（"稍后重试"），因为这确实是容量不足而非业务失败。客户端必须把 `429` 与 `200 + success:false` 分开处理——前者可重试，后者不可。

客户端实现（`agent/tools/batch_executor.py`）：

* `429` 与**传输异常**都重试，其余非 `200` 立刻抛错（`500` 不是容量压力，重试只是重复失败）。
* `Retry-After` 支持**秒数**与 **HTTP-date** 两种写法（RFC 9110 都允许）；缺失或不可解析时退化为指数退避。
* 退避上限 `SECLOOP_RETRY_MAX_SLEEP_S`（默认 `60`）——一个恶意或有 bug 的 `Retry-After` 不能把训练拖死。
* 重试次数 `SECLOOP_RETRY_ATTEMPTS`（默认 `4`）。
* 预算耗尽后抛 **`SOCBusyError`**：它是 `SOCUnavailableError` 的子类（既有处理者继续生效），
  但类型不同，好让奖励层把它与"策略失败"分开——见 §10.2 的"排除而非记 0"。

响应体另外携带三个**加性**字段，供证据文件记录"这一轮为什么全 `false`"：`abort_kind`、
`attack_unreached`、`caused_by_defence`（语义见 §2.1）。

### 3.2 其他端点

| 方法 | 路径 | 响应 |
|---|---|---|
| `GET` | `/health` | 8 键：`{"status":"ok","attack_modes":["sqli"],"vm_pool_size":1,"available_pairs":1,"vagrant_root":"…","api_version":"1.0","pre_attack_sample":false,"require_snapshot":true}`。后 5 个是**诊断用**：客户端须忽略未知键，不要严格比对。`pre_attack_sample` 是 `PipelineConfig` 的**出厂默认值 false**（`SOC_PRE_ATTACK_SAMPLE=1` 才开启，开启后每轮多跑一次攻击） |
| `GET` | `/pairs` | `{"pairs":[{"name":"pair-0","red_vm":"kali","blue_vm":"target","in_use":false}]}` |
| `GET` | `/capabilities` | **`T_A` 的唯一来源**，见 §3.2.1 |

#### 3.2.1 `GET /capabilities` —— 「当前环境有哪些工具」

论文 Eq.3 把 `T_A` 定义为**当前环境可用的工具**。那就必须**问环境**，不能由配置或按 OS 写死的表来说。
本端点是**测量**：服务端对靶机跑一次探测（`uname -s`、`sudo -n true`、逐个 `command -v`），把观测结果与由此推出的工具集一起返回。

```json
{"vm":"target","os":"Linux","renderer":"posix","root_available":true,
 "binaries":["bash","iptables","sh"],
 "available_tools":["block_ip","bash"],
 "unavailable":{"powershell":["needs a powershell session, target offers posix",
                              "none of ['pwsh','powershell.exe','powershell'] is on the target"]},
 "probe_command":"…实际执行的脚本…","detail":"…原始输出（截断）…"}
```

查询参数 `?vm=<name>` 可选，默认取池中第一对的 `blue_vm`。真机实测（本仓库 Lab）耗时约 **19 s**（一次
Vagrant SSH 往返），所以服务端**按 VM 缓存**探测结果，不每轮重探。

**失败语义**：探测不出来 → **HTTP 503**，`available_tools` 为 `null` 并给出 `error` 与 `hint`。
**绝不**回落到"整张目录"或"空集"——那两种回落都是猜测，而猜测正是这类错误的成因。
客户端拿到 503 必须报错，不得自行编造 `T_A`。

### 3.3 VM 池

- 默认 **1 对**（`kali` + `target`）。
- 可通过环境变量 `SOAR_VM_POOL`（JSON 数组）扩展，格式：
  ```json
  [{"name":"pair-0","red_vm":"kali","blue_vm":"target"}]
  ```
- 池的占用/释放**必须加锁**（用无锁 dict 的话，并发会重复分配）。

---

## 4. 反馈向量语义（PEV）—— 测量与极性分离

> 这是本项目最容易写错的地方，请严格遵守。

| 字段 | 定义 | 取值 | 论文 |
|---|---|---|---|
| `rs_exe` | `mean(tool.success)` over 策略内全部工具 | `[0,1]` 浮点 | Eq.10 |
| `rs_attack` | `(1/m)·Σ(stage.success)` —— **攻击分段的原始成功率** | `[0,1]` 浮点 | Eq.11 **字面值** |
| `rs_service` | 真实探活：靶机 HTTP 可达 **且** 攻击机可达 | **严格 `{0,1}`** | Eq.12 |
| `F_i` | `rs_exe + rs_attack + rs_service` | `[0,3]` | Eq.13 |

### 4.1 硬性规则

1. **PEV 绝不取反。** `rs_attack` 就是攻击成功了多少，不做 `1 - x`。`1 - attack_rate` 把**测量与极性**混为一谈，禁止使用。
2. **空分段必须是 `0.0`。** `stages == []` 时返回 `1.0` 会让"攻击根本没跑"反而拿满分。必须返回 `0.0` 并记 WARNING。
3. **极性只在奖励层。** `R_eva = 1 - rs_attack` 在 `training/src/open_r1/rewards.py` 里计算，**不由 `rs_service` 门控**（见 §10.2）。这与论文 Eq.20 一致：`R_eva = W_BATTLE-FIELD ∈[0,1]`，正文说明"1 = 执行后没有告警"。PEV 另提供 `defense_effectiveness = 1 - rs_attack` 作为**只读便利字段**，仅供展示/日志，**不得**用它替代 `rs_attack` 参与 Eq.13。
4. `rs_service` 必须是**真实探测**（HTTP 请求 + 连通性检查），不得用"blue 命令成功 + attack_score 阈值"之类的启发式代理。**默认要求标记命中**（`strict_marker` 默认 `True`）：只回 `200` 不算服务可用，否则代理/门户页/被替换的页面都会被读成"服务正常"。换靶机时保留 `index.php` 的锚点，或设 `SOC_TARGET_MARKER_STRICT=0` / `SOC_TARGET_MARKER=<你的锚点>`。
5. **`rs_attack` 是无权平均，不含 `weight`。** 论文 Eq.11 的字面形式是 `(1/m)·Σ f_exe(p_j)`，分母是分段**个数** `m`。`stages[].weight` 只服务于攻击脚本自报的加权 `score`（§2.1）。忽略 `weight` 不是疏漏：它正是 Eq.11 的形式。
6. PEV 必须**纯函数式**：`validate(tool_results, attack_result, service_probe, pre_attack_stages=None) -> dict`（第 4 个参数是可选的诊断输入，**不参与** Eq.10–13 的计算），不自己发网络请求，便于单元测试。
7. **"没测到"与"挡住了"必须分开。** RTC 必须读 `abort_kind`（§2.1）：只有 `target-unreachable` 才算"被挡住"（`rs_attack` 取上报阶段 ⇒ 全 `false` ⇒ `0.0`），并置 `attack_unreached = True`；其余任何 kind（含缺失时的 `unclassified`）都是**未测量**，本轮不给分。`caused_by_defence` 只允许由前置对照（§2.1、`resolve_causation()`）写 `True`/`False`，其余一律 `None`——**"没人查过"不得冒充"已证明"**。

---

## 5. 组合策略语义（BTC / RTC / PEV 三者时序）

> 把每个工具拆成一次独立红蓝对抗，会让**组合策略从未被整体评估**。

**一轮 `POST /execute_ability` 的固定时序：**

```
1. 预攻击采样（可选，用于诊断）      RTC.run_attack()           -> pre_attack_stages
2. BTC.deploy_strategy(tools, blue)  → 一次性部署**整条策略**的全部工具
                                      → 返回逐工具结果 [{tool, success, output}, ...]
3. RTC.run_attack()                  → 对**已部署完整策略**的靶机**打一次**
                                      → 返回 {score, stages}
4. PEV.validate(...)                 → rs_exe（来自步骤 2）
                                        rs_attack（来自步骤 3）
                                        rs_service（真实探活）
                                        F_i
5. BTC.restore_snapshot(blue) + RTC 无需恢复；池释放
```

**关键点**
- `rs_exe` 与 `rs_attack` **来自同一次部署、同一次攻击**，而非 N 次独立对抗。
- 每轮结束**必须恢复快照**，保证下一轮从干净状态开始。
- `defense_effectiveness = 1 - rs_attack`。

**并发：N 对 VM 与训练侧并发度要匹配。** SOC 以多线程处理请求，`SOAR_VM_POOL`（§3.3）
可以配置 **N 对** VM，池的 `acquire()` 带锁与超时（`SOC_POOL_TIMEOUT_S`，默认 300 s）。
训练侧 `sa_cascade_reward` 用 `ThreadPoolExecutor` 同时提交本批的多个 completion，
并发度由 `SECLOOP_REWARD_CONCURRENCY`（默认 `4`，上限为本批 completion 数）控制；
`executor.map` 保证返回顺序，`rewards[i]` 仍对应 `completions[i]`。两者要匹配：
并发度大于池里的配对数时，多出来的线程会在 `acquire()` 上排队，而不是并行跑轮次；
等满 `SOC_POOL_TIMEOUT_S` 仍拿不到配对，该轮变成可重试失败（§3.1、§10.2）。

---

## 6. 工具注册表（**全仓唯一一张表**，3 个工具）

**权威定义：`battlefield/soc/tool_catalogue.py` 的 `TOOL_CATALOGUE`。** 由**执行侧拥有**，因为论文 Eq.3 把 `T_A` 定义为"**当前环境**可用的工具"——"这个环境能跑什么"是服务端的事实，不是客户端的愿望。

| `tool` | `params` | `template`（SOC 渲染） | 所需解释器 `renderer` | 探测什么 `requires_any` | 需 root | `privileged` |
|---|---|---|---|---|---|---|
| `block_ip` | `{"ip": "<IPv4>"}` | `iptables -I INPUT -s {ip} -j DROP` | `posix` | `iptables` | 是 | 是 |
| `bash` | `{"command": "<str>"}` | `{command}` | `posix` | `bash` **或** `sh` | 否 | 否 |
| `powershell` | `{"command": "<str>"}` | `{command}` | `powershell` | `pwsh`/`powershell.exe`/`powershell` | 否 | 否 |

表里的"执行的命令"**不单独存储**，而是由 `template` 派生（`{ip}` → `<ip>`）：两处相似字段描述同一件事会造成不一致，所以命令只有一个来源。

**注意这张表没有"平台"列，只有"要探测什么"。** 为每个工具写死 `platforms={"Linux"}` 并按 `SOC_PLATFORM` 过滤，只是把"配置里多列了一个工具"换成了"一张表声称知道某台机器有什么"。表无从知道：这台机器可能**没装 `iptables`**、`sudo` 可能**不工作**、机器也可能根本不是配置里写的那个 OS。所以：

- **可用性是测量出来的**：`/capabilities` 探测靶机（OS / `sudo -n` / 各可执行文件），`names_from_capabilities(renderer, binaries, root_available)` 据此推出 `T_A`。**下面这张表里的"本仓库是否提供"没有一列是写死的。**
- **两道闸门都要满足**：① 本仓库的 SOC 能**驱动**该工具所需的解释器（`SOC_RENDERERS = {"posix"}`）；② **靶机**满足该工具的需求。任一不满足即不提供。
- 真机实测（Lab 靶机 `target`）：`os=Linux, renderer=posix, root_available=true, binaries=[bash, iptables, sh]` → `available_tools=[block_ip, bash]`；`powershell` 因**两条各自独立测得**的原因不可用。

| 环境（探测所得） | `T_A` |
|---|---|
| Linux + `iptables` + root 可用 | `block_ip, bash` |
| Linux + 只有 `sh`，无 root | `bash` |
| Linux + `iptables` 但 **无 root** | `bash` ← `block_ip` 被剔除 |
| Linux + 什么都没装 | *（空）* ← 拒绝构建空 `T_A` 的提示词 |
| Windows + `powershell` | *（空）* ← SOC 驱动不了 PowerShell 会话 |
| Darwin + `bash` + `iptables` + root | `block_ip, bash` |

**这正是"按 OS 注入不同工具"的落地方式**：不是查一张静态表，而是先分辨靶机的解释器家族（`renderer_for_os`），再逐个工具检查**它实际需要的东西在不在**。同一份代码在不同机器上给出不同的 `T_A`，上表就是证据。

- **只有一张表。** `agent/tools/security_tools.py` 不定义工具，只负责把客户端的 `func`/校验器**绑定**到目录条目上（集合不一致会在 import 期报错）；`training/src/open_r1/utils/security_tools.py` 仍是 re-export。
- **成员资格 ≠ 环境可用性。** `TOOL_SPECS`/`TOOL_NAMES` 是**完整目录**（与主机无关，供奖励层的名称校验用）；`create_security_tools(available=…)` 只注册**探测结果里真的能跑**的条目。因此 `T_A`、LLM 允许调用的工具集、`environment["tools"]` 三者必然一致。
- **`powershell` 在本仓库里永远不会被执行**：靶机没有 `pwsh`，而且 SOC 的渲染器只有 POSIX。`build_command` 对它会**大声抛 `ToolSpecError`**。把它当 bash 跑并记为成功会**凭空抬高 `rs_exe`**。
- `agent/config.json` **不**声明 `environment.tools`。`--tools`/`environment.tools` 仍可作为**显式声明**使用，但它只是**声明、不是测量**：结果会标成 `tool_source="declared"` 并给出 WARNING。
- `privileged: True` 的工具以 **`sudo -n`** 前缀执行（`iptables` 需要 `CAP_NET_ADMIN`）；也正是它使得"有没有 root"成为可用性的一部分，而不是假定。
- SOC 侧 `BlueTeamController.supported_tools` 来自**探测缓存**（本 Lab：`['bash', 'block_ip']`），`build_command` 直接委托给 `tool_catalogue.build_command` 并把探测到的集合传进去，所以 SOC 与目录不可能对"能不能跑"产生分歧。
- `get_tool_descriptions(available)` 输出的文本即提示词里的 `T_A`（论文 Eq.3），格式：
  ```
  - block_ip: Block an IP address using iptables. Parameters: ip (string, required)
  ```
- **扩展一个工具**：步骤见 `docs/reproduction.md`；门禁 §12 会拦住第二张工具表、按 OS 写死的工具表、跳过靶机探测，以及 `config.json` 自带的工具表。

---

## 7. LLM 端点契约（**评估与训练共用**）

> 三条路径必须共用同一个抽象：
> ① Agent 生成策略 ② 训练时 `use_vllm` 的生成 ③ 训练时惩罚 judge。

### 7.1 唯一配置形态

```json
{
  "llm": {
    "base_url": "http://127.0.0.1:8000/v1",
    "model": "<served-model-name>",
    "api_key_env": "LLM_API_KEY",
    "temperature": 0.0,
    "timeout_s": 120
  }
}
```

规则：
- 只允许 **OpenAI 兼容的 serving 协议**（vLLM / SGLang / Ollama / TGI 原生支持）。
- `api_key_env` 存的是**环境变量名**，不是值；仓库内**零密钥**。
- **禁止**出现任何云厂商名、任何外部或私有部署端点（端点一律走 §7.1 的本地 serving 约定）。
- 未配置端点时，**必须显式报错**，不得静默返回 0.0 或空策略。
- `train.sh` 一律使用 `${VAR:-}` 模板形式。

### 7.2 连通性自检

提供统一自检：`python -m agent.llm.llm_interface --check`，打印
`LLM endpoint OK: <base_url> model=<model>` 或明确失败原因。

---

## 8. 提示词契约（论文 Eq.4：`P = [C, T_A, E]`）

三段必须齐全，顺序固定：

| 段 | 来源 | 说明 |
|---|---|---|
| `C` | 摘要器 `S_r`（§9） | 压缩后的告警摘要 |
| `T_A` | `tool_manager.get_tool_descriptions()` | 可用工具清单 |
| `E` | 数据集/环境描述 | `Platform` + `Description` + 环境内可用工具 |

**要求**：`agent/llm/llm_interface.py` 与 `training/src/open_r1/grpo.py` 必须产出**结构一致**的提示词（推理侧不得缺 `E`）。

输出必须是 JSON 工具调用数组：

```json
[{"tool": "block_ip", "params": {"ip": "192.168.57.199"}}]
```

---

## 9. 摘要器 `S_r` 契约（`ids/combine_ids_log.py`）

```python
def summarize_fastlog(path: str | Path, window_s: int = 300) -> str
def summarize_lines(lines: Iterable[str], window_s: int = 300) -> str
```

- 输入：**真实** Suricata `fast.log` 行。
- 处理：按 `(attack_type, source_ip)` 聚合，在 `window_s` 窗口内压缩。
- 输出：结构化自然语言摘要（对应论文 Eq.2 的 `C`），**空输入返回空字符串**。
- 不得伪造任何日志行。

---

## 10. 训练侧契约（`training/**`）

### 10.1 SA-GRPO 的 **5 个算法值（6 个 YAML 键）** 必须显式写在 recipe YAML

`training/recipes/Qwen2.5-7B-Instruct/grpo/config.yaml`：

```yaml
num_generations: 7       # 组大小 G（论文 Table IV）
scale_rewards: false     # 优势估计不除以标准差
beta: 0.0                # 去掉 KL 项
epsilon: 0.2             # ε_low
epsilon_high: 0.28       # Clip-Higher 的 ε_high
loss_type: dr_grpo       # 见下方说明
reward_funcs:
  - sa_cascade
```

**关于 `loss_type`**：论文 Table IV 没有列出这一项，但论文 Eq.14 的目标函数写作

```
J(θ) = E[ (1/G) · Σ_{i=1..G} Σ_{t=1..|o_i|} min( γ_{i,t}·Â_{i,t}, clip_{i,t}·Â_{i,t} ) ]
```

注意 **分母只有 `1/G`，没有 `1/|o_i|`** —— 即不做逐序列长度归一化。TRL 的
`loss_type` 有三个取值：`grpo`（逐序列除以 `|o_i|`）、`bnpo`（除以批内非填充
token 总数，上游默认）、`dr_grpo`（除以常数，即 Dr. GRPO 的去除长度偏置写法）。
三者中只有 `dr_grpo` 与 Eq.14 的可见特征一致；作者训练时用的也是 `dr_grpo`，
而 TRL 的上游默认值是 `bnpo`。

因此本仓库**显式写出** `loss_type: dr_grpo`，并在注释里注明 Table IV 未列出。
理由与其余四个值相同：**显式优于隐式**——若留空走上游默认 `bnpo`，既不符合 Eq.14，
也不符合作者的实际运行，读者无从判断。

其余沿用论文 Table IV：`learning_rate: 3.0e-06`、`num_train_epochs: 1`、`per_device_train_batch_size: 4`、`gradient_accumulation_steps: 1`、`torch_dtype: bfloat16`。

**Table IV 里另外两项本仓库**不**写进 YAML，因为它们在论文自己的配置下不生效：**

| Table IV | 实际情况 |
|---|---|
| `α = 0.6` | TRL 的 `ref_model_mixup_alpha`，**上游默认值恰好就是 `0.6`** |
| `ref_model_sync_steps = 512` | TRL 的 `ref_model_sync_steps`，**上游默认值恰好就是 `512`** |

这两项属于 TR-DPO 的参考模型同步机制，由 `sync_ref_model` 开关控制，而**它的默认值是
`False`**——上游 docstring 明写 "To use this parameter, you must set
`sync_ref_model=True`"。本仓库 recipe 不设置 `sync_ref_model`；同时 `beta: 0.0` 已经
让参考模型**根本不加载**（上游：`If 0.0, the reference model is not loaded`）。
因此这两项在本配置下是**惰性的**：写与不写不改变任何一次梯度更新。

它们出现在论文 Table IV，更可能是把库默认值抄进了超参表。本仓库**刻意不写**（写进 YAML
会让读者误以为已启用），并在此如实说明，以免复现者照抄后得不到预期效果却不知原因。

### 10.1.1 训练并行度约束（来自 TRL 的硬校验）

`trl@1bca4951` 在启动时会**硬性校验**：

```
per_device_train_batch_size × num_processes × gradient_accumulation_steps
    必须能被 num_generations 整除
```

代入 Table IV（`4 × N × 1`）与 `G = 7`，得到 **`N` 必须是 7 的倍数**。
这恰好解释了论文的 **8×A800** 配置：**7 个训练 rank + 1 张卡留给生成服务**
（`use_vllm: true` 时需要独立的 `trl vllm-serve` 进程）。启动配置见
`training/recipes/accelerate_configs/zero2.yaml` 与 `training/train.sh`。

### 10.2 四级级联奖励 `sa_cascade_reward`

| 级 | 名称 | 依据 | 规则 |
|---|---|---|---|
| 1 | `R_format` | Eq.18 | JSON 合法性 + 工具名合法。**不通过 → 0.0** |
| 2 | `R_exec` | Eq.19 | `rs_exe == 1.0` 才给分（0/1 门控） |
| 3 | `R_eva` | Eq.20 | **`1 - rs_attack`**（本仓库的估计量）—— **不乘 `rs_service`**（极性在此，见 §4） |
| 4 | `P` | Eq.21 | LLM judge 的过度防御程度，**相减** |

总分 `R = R_format + R_exec + R_eva - P`，裁剪到 `[0, 3]`。
LLM judge 未配置端点时**必须报错**（不得静默返回 0.0）。

**第 3 级：挡住攻击就得这一分，不附加条件。** 论文 Eq.20 给的是
`R_eva(o_i) = W_BATTLE-FIELD(o_i) ∈[0,1]`，正文说明"**1 表示执行后没有告警**"——这正是
`README`/本文档所说的"挡住攻击就得一分"的来源，**这一层是论文的语义**。

论文给出的是 `R_eva = W_BATTLE-FIELD`（"告警的缺失"），实现因此取 `1 - rs_attack`。

`rs_service` **不参与**这一级：把 §IV-D 的"可执行 ∧ 有效防御 ∧ **不造成任何服务中断**"
合取、或 §II-C-3 的服务可用性信号读进 Eq.20，会让评估奖励变成"服务还在才算挡住"，
而 Eq.20 本身并不这样要求。

**代价要写明，不要藏起来**：一个"封掉一切流量、把靶机一并打挂"的策略也能拿
`R_eva = 1.0`，这与 §IV-D 对 "correct" 的合取读法冲突。

**在奖励函数内部，没有任何一处制衡它**——这点必须说清，不能拿 `F_i` 当挡箭牌：
`cascade_total = R_format + R_exec + R_eva - P`，`F_i`（Eq.13）**不参与**总分，`rs_service`
只被解包、校验完整性、并写进日志/实验记录，**不改变任何一分**。因此打挂靶机的策略与干净
封堵拿到**完全相同**的奖励。真正留在奖励里的只有 `R_exec`（Eq.19，要求策略至少可部署）
与第 4 级的 Eq.21 judge（`P`，需要配置 LLM 端点；未配置时必须报错而不是静默 0）。

这是一处**明确的**取舍：论文的语义要求挡住即得分，而"过度防御"只能靠 judge
与人工查看日志发现。若要恢复 §IV-D 的合取读法，必须同时改 `rewards.py`、本节与
`tests/check_repo_contract.py` §8 的结构不变量。

反方向也有代价：被 `rs_service` 门控时，一次**我们自己的**探测抖动也会连带撤掉评估奖励。
去掉门控后两边的偏差都由 judge 与人工日志承担，这是刻意选择。

字段缺失（`rs_service` 不在反馈向量里）**不等于**服务不可用：向量不完整 ⇒ 本轮**未测量**，
`R_exec = R_eva = 0.0` 并记 `WARNING`。

**容量耗尽要把样本排除，而不是记 0。** VM 池拿不到空闲配对时，客户端重试
（§3.1）后抛 `SOCBusyError`。这是**我们的问题，不是策略的问题**：记 `0.0` 会教模型"一个好策略
失败了"。所以本轮被**排除出该样本**：

* TRL 的奖励契约是"每个 completion 一个 float"，**没有**"丢掉一个样本"的表达能力，
  所以整批被**中性化**——本批所有 completion 拿到**同一个** `EXCLUDED_BATCH_REWARD`。
  在 GRPO 里同一组内奖励完全相同 ⇒ 优势为 0 ⇒ 梯度为 0，即"这一批什么也没学到，
  也没学错"。
* 上述结论来自 `requirements` 里 pin 的那个 commit 的 `GRPOTrainer.compute_loss`
  源码：它先 `rewards = (rewards_per_func * weights).nansum(dim=1)`，
  再 `advantages = rewards - mean_grouped_rewards`；仅当 `scale_rewards` 为真时才除以
  `std_grouped_rewards`，而 SA-GRPO 的配方设 `scale_rewards: false`。整批取同一常数后
  每组均值为该常数，优势恒为 0。
* **不要"简化"成返回 `NaN`。** 同一份源码里 TRL 用 `nansum` 合并各奖励函数的输出：
  单个 `NaN` 会被 `nansum` 当成 0，于是"被排除"的样本会**静默变回 0 分样本**，
  正好是我们要避免的那件事。
* 代价是真实的，因此**写进日志**：一个样本被卡住，代价是本批一次训练步。这是与"教坏模型"
  之间刻意的取舍。要做**按组/按样本**排除，需要给 `GRPOTrainer` 打子类补丁去改
  `advantages` 对应行（`advantages` 已按 completion 索引，机制上可行），本仓库没有为此
  分叉 TRL——这也是 `requirements` 里把 TRL 固定在某个 commit 的原因。
* `SECLOOP_RETRYABLE_POLICY=zero` 可恢复旧行为（记 0）以便复现旧 run；默认是 `exclude`。

> **这不是"把失败藏起来"**：`200 + success:false`（策略被拒、部署失败、攻击没测到）依旧记
> `0.0` 并照常进入训练。只有**可重试的传输失败**才被排除，判据由 §3.1 的类型区分保证。

> **为什么第 3 级不乘 `rs_service`。** 乘上去会引入另一个方向的偏差：一旦 `rs_service`
> 抖动（我们自己的探测失败），一个真正挡住了攻击的策略也会被撤掉评估奖励。两个方向
> 都有偏差，本仓库选择让第 3 级只回答"有没有告警"，把"是否过度防御"留给 Eq.21 的 judge
> 与人工查看日志。若将来要采用 §IV-D 的合取读法，**必须同时**改 `rewards.py` 与本节，
> 并同步 `tests/check_repo_contract.py` §8 的不变量（它断言 `R_eva` **不得**被
> `rs_service` 门控）。

**第 4 级的命名，论文自己两处不一致，本仓库以实际流程为准。** §II-B-4 把它称作
*reasoning verification*（"策略与攻击描述 L 是否对齐"），但 §III-B-3 描述的实际流程是
"评估之后进入 **penalty** 阶段"、Eq.21 给出 `P(o_i) = 1 - W_LLM(o_i)`。本仓库实现的是
后者（LLM judge 判定的过度防御程度），并把"策略与攻击不相关/过度"视为它的一个特例。
**这是本仓库与论文之间已知的语义差异**：若按 §II-B-4 的字面描述寻找一个独立的
"reasoning verification 模块"，在本仓库里找不到对应的独立实现。

### 10.3 不包含的内容

- 不包含 `training/src/rloo/`：论文 RLOO baseline 的重复实现，且是未完成 stub。
- **不 vendor** `trl`；`requirements/training.txt` 固定到上游提交 `1bca49515ecd5b85d16e68c42c76670e252e19f1`（等价 `trl==0.18.0`）。

---

## 11. 靶机契约（`target/**`）

| 路径 | 作用 | 硬性要求 |
|---|---|---|
| `target/webapp/index.php` | 探活锚点 | 恒返回 HTTP 200 + 固定字符串 `SecLoop target OK` |
| `target/webapp/search.php` | 漏洞点 | 把 `id` 参数**真拼接**进 SQL（非参数化），可被 `SLEEP()` 时间盲注判定 |
| `target/webapp/schema.sql` | 建库 | 库名/表名/列名/一行数据都需与攻击脚本 §2.3 的 5 段对应 |
| `target/suricata/local.rules` | 检测 | **≥6 条**，`sid` 自 `1000001` 起**连续无缺口**（不设上限：扩展场景时按下一个空闲 `sid` 追加即可）；匹配本靶机 HTTP 的 SQLi 特征；须能被 `suricata -T` 语法校验通过 |
| `target/suricata/README.md` | 说明 | 含 ET Open 加载说明 |
| `target/README.md` | 警告 | 明确"故意脆弱、仅隔离网络、禁止公网暴露" |

**检测真实性要求**：Suricata 必须真正观察真实 HTTP 流量并写出真实 `fast.log`；**禁止**脚本自己往日志里写假告警。

---

## 12. 契约自检清单（集成复查用）

- [ ] 全树 `python -c "import ast; ast.parse(open(f).read())"` 无 SyntaxError
- [ ] `battlefield`、`agent`、`training` 三处均有 `# SPDX-License-Identifier: Apache-2.0`
- [ ] 全树扫描无**凭据形状**的字符串（各家 key 前缀、token 前缀、密钥赋值），无**云厂商名**，无**私有域名与内网 IP**，无**个人标识（学号/用户名/邮箱）**
      —— 具体匹配模式见 `tests/check_repo_contract.py`，此处刻意不写出字面量：**一份"禁止出现"的清单本身也是一次泄露**。
- [ ] `[RESULT]` JSON 契约在攻击脚本与 RTC 两侧一致；**字段顺序**含末位 `abort_kind`，且两处 `ABORT_KINDS` 词表相等（`tests/lab/test_abort_kind_contract.py`）
- [ ] `abort_kind` 的默认是 `unclassified`（未测量），**不是** `target-unreachable`；`check_health()`/`calibrate()` 的每一处 `raise` 都带对分类（AST 断言）
- [ ] 只有 `target-unreachable` 算"被挡住"（`attack_unreached=True`），其余 kind 一律未测量；`caused_by_defence` 只能来自前置对照，`None` 不等于 `True`
- [ ] PEV 空分段返回 `0.0`（不是 `1.0`）
- [ ] `rs_attack` 在 PEV 中**不取反**；`R_eva = 1 - rs_attack`（本仓库对 Eq.20 的估计量）只在奖励里，且**没有**乘 `rs_service`（`tests/check_repo_contract.py` §8 以 AST 断言此事）
- [ ] `rs_service` 严格 `{0,1}` 且来自真实探测，并计入 `F_i`（Eq.13）；**缺失该字段 ⇒ 本轮未测量**，`R_exec = R_eva = 0.0`（不得默认给分，也不得拿它给第 3 级加门控）
- [ ] 可重试的传输失败（`429` 容量耗尽）**不写成 0 分**：客户端用 `Retry-After` 退避重试，耗尽后把该样本**排除**而非记 0
- [ ] `batch_executor._dataset_path()` 路径正确
- [ ] 提示词同时含 `C`、`T_A`、`E`（agent 与 training 两侧）
- [ ] `config.yaml` 显式含 `scale_rewards/beta/epsilon/epsilon_high/num_generations`
- [ ] 无 `training/src/rloo/`、无 `agent/rag/`、无 vendored `trl/`
- [ ] 全树无 `__pycache__`/`*.pyc`，且无游离 `.pytest_cache`（`pytest.ini` 明确禁止）
- [ ] 全树文本文件为 LF、无 BOM、**均有尾换行**（`check_repo_contract.py` §4 强制）
- [ ] 仓库内零密钥、零内网端点、零云厂商名
