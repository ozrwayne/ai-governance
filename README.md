# AI Governance — 外部审计快照

本仓库保存用户从 Mac mini 复制的两个治理目录的全部文件，供外部审计。

| 仓库目录 | Mac mini 来源 |
| --- | --- |
| `workspace/` | `/Users/rwmacmini/RW/governance/` |
| `system/` | `/Library/Governance/` |

## 阅读入口

- [宪法 C2026-001 v1](system/register/C2026-001/v1.md)
- [代理动作程序法 S2026-002 v2](system/register/S2026-002/v2.md)
- [中枢设备存储法 S2026-003 v1](system/register/S2026-003/v1.md)
- [登记索引](system/register/index.yaml)及[登记链](system/register/chain.log)
- [代理动作程序法修正案](system/register/S2026-004/v1.md)
- [最新代理动作配置公报](system/register/G2026-007.md)
- [已部署闸门](system/gate/)、[登记工具](system/tools/)
- [草案与开发代码](workspace/drafts/)、[动作记录](workspace/records/)、[状态](workspace/state/)

当前版本依据随副本提供的登记索引识别。草案和未登记汇编预览保留原样，不视为正式生效文本。

## 完整性与还原

共保留 67 个原始文件，包括隐藏文件、缓存、记录与程序二进制，不修改原始内容。`MANIFEST.json` 记录各文件 SHA-256、大小、复制后的权限及全部目录（含空目录）。

`system/bin/omp` 原文件为 220,479,632 字节，分成 6 块保存在 `large-files/system/bin/omp/`，避免单个 Git 文件过大。它的全部字节均保留；运行下述还原命令会重新生成原文件。

```bash
python3 verify_restore.py
python3 verify_restore.py --restore ../ai-governance-restored
```

还原目标必须尚不存在。脚本逐文件校验、恢复分块文件和空目录，不运行任何治理程序。

## 审计范围与限制

此快照覆盖用户提供的两个目录，不能据此宣称覆盖 Mac mini 的全部运行环境。两个目录通过 SCP 分别复制，并非同一时刻的原子快照。校验值针对收到的 Linux 副本；没有独立比对 Mac mini 上的源文件，也未保留或核验原机器的所有权、ACL 与扩展属性。

公报引用的目录外配置（例如 `/Library/Application Support/ClaudeCode/managed-settings.json`、用户代理配置）不在本次两个目录副本内。审计者应根据公报与代码进一步核对实际机器。仓库制作过程没有执行安装脚本、登记操作或改变现行法律，亦未执行治理系统的行为测试。
