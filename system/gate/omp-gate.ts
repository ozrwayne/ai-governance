// Protected omp extension: UI state is never an authorization credential.
const PYTHON = "/usr/bin/python3";
const GATE = "/Library/Governance/gate/gate.py";

interface ExecResult { stdout: string; stderr: string; code: number }
interface ToolCallEvent { toolName: string; toolCallId: string; input: unknown }
interface ToolResultEvent {
	toolName: string;
	toolCallId: string;
	isError: boolean;
	content: Array<{ type: string; text?: string }>;
}
interface GateContext {
	cwd: string;
	agent?: { kind: string; id: string; name: string };
	model?: { provider: string; id: string };
	sessionManager?: { getSessionId(): string };
}
type ToolCallResult = { block: true; reason: string } | undefined;
interface GateApi {
	exec(command: string, args: string[], options: { cwd: string }): Promise<ExecResult>;
	on(event: "tool_call", handler: (event: ToolCallEvent, ctx: GateContext) => Promise<ToolCallResult>): void;
	on(event: "tool_result", handler: (event: ToolResultEvent, ctx: GateContext) => Promise<void>): void;
}
interface Verdict { decision?: string; reason?: string; read_receipt?: string }

export default function gate(pi: GateApi): void {
	const receipts = new Map<string, string>();
	pi.on("tool_call", async (event, ctx) => {
		const payload = {
			client: "omp",
			session: ctx.sessionManager?.getSessionId() ?? "unknown",
			agent: ctx.agent ? { kind: ctx.agent.kind, id: ctx.agent.id, name: ctx.agent.name } : null,
			model: ctx.model ? { provider: ctx.model.provider, id: ctx.model.id } : null,
			cwd: ctx.cwd,
			tool: event.toolName,
			input: event.input,
		};
		try {
			const result = await pi.exec(PYTHON, ["-I", GATE, "decide", JSON.stringify(payload)], { cwd: ctx.cwd });
			if (result.code !== 0) throw new Error(result.stderr || `gate exit ${result.code}`);
			const verdict = JSON.parse(result.stdout) as Verdict;
			if (verdict.decision !== "allow") return { block: true, reason: verdict.reason ?? "闸门程序拦下该动作。" };
			if (verdict.read_receipt && event.toolCallId) receipts.set(event.toolCallId, verdict.read_receipt);
			return undefined;
		} catch (error) {
			return { block: true, reason: `受保护闸门无法审查，动作已拦下：${String(error)}` };
		}
	});
	pi.on("tool_result", async (event, ctx) => {
		const receipt = receipts.get(event.toolCallId);
		if (!receipt) return;
		receipts.delete(event.toolCallId);
		const text = (event.content ?? []).filter(part => part.type === "text").map(part => part.text ?? "").join("\n");
		// Failure never grants reading credit; the next gated action remains denied.
		try {
			await pi.exec(PYTHON, ["-I", GATE, "outcome", JSON.stringify({ read_receipt: receipt, is_error: event.isError === true, text })], { cwd: ctx.cwd });
		} catch { /* broker did not record the read; no local fallback */ }
	});
}
