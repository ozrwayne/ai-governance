# 公报：代理动作配置

依《代理动作程序法》的闸门、停止与记录规定，更新代理动作配置。以本公报的完整配置替代此前同名公报的运行配置；历史公报保留。

1. 闸门程序与入口路径不变。新增受保护的本机授权服务，核验任务授权和委托来源。
2. 停止标志、动作记录、读取状态与回滚快照迁入系统保护目录，代理不得直接写入。停止请求由授权服务接收，任何来源均可提出。
3. 私密范围不变，暂不指定任何可读取该范围的代理；在可信本地模型来源核验完成并重新确认配置前，所有代理均不得读取私密资料。普通资料与技能读取不受此项限制。
4. 此次公报只登记运行配置变更；日常任务授权不逐项发布公报。

```json
{
  "gate": {
    "program": "/Library/Governance/gate/gate.py",
    "omp_extension": "/Library/Governance/gate/omp-gate.ts",
    "claude_code_settings": "/Library/Application Support/ClaudeCode/managed-settings.json",
    "authorization_program": "/Library/Governance/gate/authorization.py",
    "authorization_socket": "/Library/Governance/run/authorization.sock"
  },
  "private_readers": {
    "providers": []
  },
  "devices": {
    "mac-mini": {
      "hostname": "Roland-Mac-Mini",
      "stop_requests": "/Library/Governance/authorization/runtime/mac-mini/stop-requests.jsonl",
      "stop_clears": "/Library/Governance/authorization/runtime/mac-mini/stop-clears.jsonl",
      "records": "/Library/Governance/authorization/runtime/mac-mini/records.jsonl",
      "state": "/Library/Governance/authorization/runtime/mac-mini/read-state",
      "snapshots": "/Library/Governance/authorization/runtime/mac-mini/snapshots",
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
