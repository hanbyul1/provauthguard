import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const LOG_DIR = path.join(os.homedir(), "guardian-study", "logs");
const LOG_FILE = path.join(LOG_DIR, "openclaw_tool_events.jsonl");

export default definePluginEntry({
  id: "guardian-monitor",
  name: "Guardian Monitor",

  register(api) {
    api.on("before_tool_call", async (event, ctx) => {
      const record = {
        timestamp: new Date().toISOString(),

        actor: "worker",

        toolName: event.toolName,
        params: event.params,
        derivedPaths: event.derivedPaths ?? [],

        toolKind: event.toolKind ?? null,
        toolInputKind: event.toolInputKind ?? null,

        runId: event.runId ?? ctx.runId ?? null,
        toolCallId: event.toolCallId ?? ctx.toolCallId ?? null,
        agentId: ctx.agentId ?? null,

        mode: "shadow"
      };

      fs.mkdirSync(LOG_DIR, { recursive: true });

      fs.appendFileSync(
        LOG_FILE,
        JSON.stringify(record) + "\n",
        "utf8"
      );

      // Shadow mode:
      // observe and record only.
      // Returning nothing allows the tool call to continue.
      return;
    });
  },
});
