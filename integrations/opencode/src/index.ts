/**
 * nixis-opencode — governance plugin for OpenCode.
 *
 * Subscribes to tool-call events on OpenCode's event bus and calls the
 * nixis-daemon HTTP API to classify and audit each invocation.
 *
 * Wiring into OpenCode:
 *   import { NixisPlugin } from "nixis-opencode"
 *   // Register with OpenCode's plugin registry (exact API depends on OpenCode version):
 *   opencode.plugins.register(NixisPlugin)
 *
 * The plugin calls POST http://127.0.0.1:9091/v1/check for each tool call.
 * If the daemon is unreachable it fails open — the tool call is NOT blocked.
 *
 * Event shape (from OpenCode's session/event.ts):
 *   session.next.tool.called → ToolCalledEvent
 */

/** Payload emitted by OpenCode for each tool invocation. */
export interface ToolCalledEvent {
  callID: string
  tool: { name: string }
  input: Record<string, unknown>
  sessionID: string
  timestamp: number
}

/** Wire request sent to nixis-daemon /v1/check. */
interface NixisCheckRequest {
  tool: string
  args: Record<string, unknown>
  session_id: string
}

/** Wire response from nixis-daemon /v1/check. */
interface NixisCheckResponse {
  decision?: {
    action?: string
    reason?: string
    policy_id?: string
  }
  latency_ns?: number
}

const NIXIS_CHECK_URL = "http://127.0.0.1:9091/v1/check"
/** 200 ms — matches the nixis-hook total budget. */
const TIMEOUT_MS = 200

/**
 * Call nixis-daemon to classify a tool invocation.
 *
 * Returns the parsed response, or null if the daemon is unreachable.
 */
async function callNixis(
  toolName: string,
  args: Record<string, unknown>,
  sessionID: string,
): Promise<NixisCheckResponse | null> {
  const body: NixisCheckRequest = { tool: toolName, args, session_id: sessionID }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)

  try {
    const resp = await fetch(NIXIS_CHECK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
    if (!resp.ok) {
      return null
    }
    return (await resp.json()) as NixisCheckResponse
  } catch {
    // Daemon unreachable, timeout, or parse error — fail open.
    return null
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Handle a tool-call event from OpenCode.
 *
 * Returns a block decision object when nixis denies the call, or undefined
 * to allow the tool to proceed.
 *
 * @example
 * // Wire into OpenCode's event bus (pseudo-code):
 * eventBus.on("session.next.tool.called", async (event: ToolCalledEvent) => {
 *   const block = await onToolCalled(event)
 *   if (block) throw new Error(block.reason)
 * })
 */
export async function onToolCalled(
  event: ToolCalledEvent,
): Promise<{ decision: "block"; reason: string } | undefined> {
  const resp = await callNixis(event.tool.name, event.input, event.sessionID)

  if (resp === null) {
    // Daemon unavailable — fail open.
    return undefined
  }

  const action = resp.decision?.action ?? "allow"
  if (action === "deny") {
    return {
      decision: "block",
      reason: resp.decision?.reason ?? "nixis policy violation",
    }
  }

  // allow / audit / require_approval — let the tool run.
  return undefined
}

/**
 * NixisPlugin is the OpenCode plugin export.
 *
 * The exact plugin registration API varies by OpenCode version. This object
 * provides the canonical hook handlers; wire them into your OpenCode setup
 * using the registration method available in your version.
 *
 * @example
 * // OpenCode PluginV2.define() pattern (if available):
 * // import { PluginV2 } from "@opencode-ai/core"
 * // export default PluginV2.define({ name: "nixis", hooks: NixisPlugin.hooks })
 */
export const NixisPlugin = {
  name: "nixis" as const,
  version: "1.0.0" as const,
  hooks: {
    /**
     * Invoked before each tool call. Return a block object to prevent execution.
     * Return undefined to allow.
     */
    "session.next.tool.called": onToolCalled,
  },
} as const
