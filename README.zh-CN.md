# SecLoop（中文说明）

**SecLoop** 是一个面向安全策略自动生成、编排、响应与反馈闭环的框架，配套
**SA-GRPO**——一种安全感知的组相对策略优化算法，用于调优生成策略的模型。

本仓库对应论文：
https://ieeexplore.ieee.org/document/11299517
> X. Cao, Y. Lin, G. Nan, et al., "Advancing LLM-Based Security Automation With
> Customized Group Relative Policy Optimization for Zero-Touch Networks,"
> *IEEE Journal on Selected Areas in Communications*, vol. 44, 2026, pp. 2669–2686.
> DOI: [10.1109/JSAC.2025.3643844](https://doi.org/10.1109/JSAC.2025.3643844)

英文主文档见 [README.md](README.md)。

---

## 三大子系统

SecLoop 通过 HTTP 串起 **观察 → 研判 → 决策 → 执行 → 反馈** 的闭环：

| 目录 | 角色 |
|---|---|
| `battlefield/` | SOC：红队控制器（RTC）、蓝队控制器（BTC）、策略执行验证器（PEV）、IaC 生成器、SOC 服务与参考 SQLi 探针 |
| `agent/` | 基于 LLM 的策略生成、工具实现绑定与命令行入口（工具**表**在 `battlefield/soc/tool_catalogue.py`） |
| `training/` | SA-GRPO 训练入口、四级级联奖励、论文同款 recipe |
| `ids/` | 告警摘要器 `S_r`（论文 Eq. 2） |
| `target/` | 参考靶机：我们自研的**故意脆弱** Web 应用 + Suricata 检测规则 |
| `vagrant/` | 两机实验环境（Kali 攻击机 + Ubuntu 靶机）的 IaC |

## 反馈向量（论文 Eq. 10–13）

| 字段 | 含义 | 取值 |
|---|---|---|
| `rs_exe` | 策略内各工具部署成功率的平均（Eq. 10） | `[0, 1]` |
| `rs_attack` | 攻击各分段的成功率（Eq. 11）——**该值越高说明防御越失败** | `[0, 1]` |
| `rs_service` | 策略执行后的服务可用性（Eq. 12） | `{0, 1}` |
| `F_i` | `rs_exe + rs_attack + rs_service`（Eq. 13） | `[0, 3]` |

> **重要**：`rs_attack` 是**原始测量值**，不做取反。防御有效性的极性
> （`1 - rs_attack`）只在**奖励层**计算；它是本仓库对论文 Eq.20 的
> `W_BATTLE-FIELD`（"没有告警"）的**估计量**——论文给了这个量、但没给具体算式。
> 挡住攻击就得这一分，不再附加条件，因此 `rs_service` 不是它的门控：
> 仍然被测量、被记录，并计入 `F_i`（Eq. 13）——但 **`F_i` 不进奖励总分**，所以奖励里
> 没有任何一项制衡"把靶机打挂"；唯一的方向性检查是 Eq. 21 的 judge（外加人工看日志）。
> 测量与极性刻意分层，详见 [docs/INTERFACES.md](docs/INTERFACES.md) §4 与 §10.2。

## SA-GRPO 的五个配置值

这五个值通过底层 GRPO 训练器的**配置**实现，而非改写目标函数代码：

| 配置 | 值 | 作用 |
|---|---|---|
| `scale_rewards` | `false` | 优势估计不除以组内标准差 |
| `beta` | `0.0` | 去掉 KL 项 |
| `epsilon` / `epsilon_high` | `0.2` / `0.28` | 非对称 Clip-Higher |
| `num_generations` | `7` | 组大小 *G* |
| `loss_type` | `dr_grpo` | Eq.14 只按 `1/G` 归一，不含逐序列长度因子 |

奖励为四级级联：格式 → 执行 → 评估 → 惩罚（Eq. 18–21），实现于
`training/src/open_r1/rewards.py`。

---

## 环境要求

| 组件 | 版本 | 说明 |
|---|---|---|
| VMware Workstation Pro | 建议 **17.6+** | 商用/教育/个人均免费，**无需许可证密钥**。17.5.2 在早前的个人使用授权下亦可用 |
| Vagrant | 2.4.x | |
| `vagrant-vmware-desktop` 插件 | 3.x | 需 `vagrant-vmware-utility` 服务 |
| Python | 3.11 | |
| 内存 / 磁盘 | 两台 VM 至少需 8 GB 空闲内存；base box 约 6 GB | |

基础镜像（首次 `vagrant up` 时自动下载）：`kalilinux/rolling`（攻击机）、
`bento/ubuntu-18.04`（靶机）。

**模型服务**：策略生成模型在**本地部署**，通过标准的 OpenAI 兼容服务协议
接入（vLLM / SGLang / TGI / Ollama 等均支持）。**推理与训练共用同一个端点
抽象**，因此一个本地服务同时支撑评估与训练。本仓库**不包含任何模型权重**。

```sh
python -m agent.llm.llm_interface --check     # 连通性自检
```

## 快速开始

```sh
cd vagrant && vagrant up                      # 1. 起实验环境
pip install -r requirements/battlefield.txt   # 2. 装 SOC 侧依赖
python battlefield/soc_server.py              # 3. 起 SOC 服务（端口 8988）
python agent/main.py --ids-summary-file /path/to/fast.log   # 4. 跑一轮闭环
```

## 道德与负责任使用

本仓库**不提供**论文评测所用的完整攻击样本集，也**不提供**任何针对第三方
系统的武器化利用代码——提供这类材料是不负责任的。我们提供的是一个自包含的
参考场景：由我们自行编写的、**故意脆弱**的 Web 应用，完整运行在**隔离的**
实验网络内，外加为打通 SecLoop 反馈闭环所必需的最小 SQLi 探针。
**切勿将实验网络暴露到互联网。**

强制性的运行约束见 [SECURITY.md](SECURITY.md)。

## 引用

如果参考了我们的代码，请考虑引用以下文章：

```bibtex
@article{cao2026secloop,
  author  = {Cao, Xinye and Lin, Yihan and Nan, Guoshun and others},
  title   = {Advancing {LLM}-Based Security Automation With Customized Group
             Relative Policy Optimization for Zero-Touch Networks},
  journal = {IEEE Journal on Selected Areas in Communications},
  volume  = {44},
  pages   = {2669--2686},
  year    = {2026},
  doi     = {10.1109/JSAC.2025.3643844}
}
```

## 许可证

Apache License 2.0，见 [LICENSE](LICENSE)；第三方组件与条款见 [NOTICE](NOTICE)。
