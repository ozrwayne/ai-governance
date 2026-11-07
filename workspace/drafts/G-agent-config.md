# 公报：代理动作配置

依 S2026-002 v1 §3、§6、§7、§9：

1. 闸门程序：`/Library/Governance/gate/gate.py`。omp 经 `/Library/Governance/gate/omp-gate.ts` 接入，Claude Code 经 `/Library/Application Support/ClaudeCode/managed-settings.json` 接入。
2. 私密范围只供以本地模型运行的代理读取。
3. 各设备的停止标志、记录位置与私密范围，载于下列配置；闸门程序依此配置运行。

```json
{
  "gate": {
    "program": "/Library/Governance/gate/gate.py",
    "omp_extension": "/Library/Governance/gate/omp-gate.ts",
    "claude_code_settings": "/Library/Application Support/ClaudeCode/managed-settings.json"
  },
  "private_readers": {
    "providers": ["ollama", "lm-studio", "llama.cpp"]
  },
  "devices": {
    "mac-mini": {
      "hostname": "Roland-Mac-Mini",
      "stop_requests": "/Users/rwmacmini/RW/governance/stop/requests.jsonl",
      "stop_clears": "/Library/Governance/stop/clears.jsonl",
      "records": "/Users/rwmacmini/RW/governance/records/mac-mini/records.jsonl",
      "state": "/Users/rwmacmini/RW/governance/state",
      "snapshots": "/Users/rwmacmini/RW/governance/snapshots",
      "private": ["/Users/rwmacmini/RW/知识库/00-09 中台与共享/04 人脉"],
      "protected": [
        "/Users/rwmacmini/.omp/agent/config.yml",
        "/Users/rwmacmini/.omp/agent/extensions",
        "/Users/rwmacmini/.claude/settings.json",
        "/Users/rwmacmini/.claude/settings.local.json",
        "/Users/rwmacmini/.local/bin/omp",
        "/Users/rwmacmini/.local/bin/claude"
      ]
    }
  }
}
```
