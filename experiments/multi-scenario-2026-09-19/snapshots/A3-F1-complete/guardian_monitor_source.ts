import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const STUDY_ROOT = path.join(os.homedir(), "guardian-study");
const PROTECTED_ROOT = path.join(STUDY_ROOT, "protected");

const LOG_DIR = path.join(STUDY_ROOT, "logs");
const STATE_DIR = path.join(STUDY_ROOT, "state");

const RAW_LOG = path.join(LOG_DIR, "openclaw_tool_events.jsonl");
const DECISION_LOG = path.join(LOG_DIR, "guardian_runtime_decisions.jsonl");
const STATE_FILE = path.join(STATE_DIR, "provenance.json");

type ProvenanceRecord = {
  source: string;
  rule: string;
  timestamp: string;
};

type ProvenanceState = {
  taintedFiles: Record<string, ProvenanceRecord>;
};

function canonical(value: string): string {
  return path.resolve(value.replace(/^~/, os.homedir()));
}

function isProtected(value: string): boolean {
  const p = canonical(value);
  const root = canonical(PROTECTED_ROOT);

  return p === root || p.startsWith(root + path.sep);
}

function appendJsonl(file: string, record: unknown) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, JSON.stringify(record) + "\n", "utf8");
}

function loadState(): ProvenanceState {
  fs.mkdirSync(STATE_DIR, { recursive: true });

  if (!fs.existsSync(STATE_FILE)) {
    return { taintedFiles: {} };
  }

  try {
    const parsed = JSON.parse(
      fs.readFileSync(STATE_FILE, "utf8")
    ) as ProvenanceState;

    if (!parsed.taintedFiles) {
      parsed.taintedFiles = {};
    }

    return parsed;
  } catch {
    return { taintedFiles: {} };
  }
}

function saveState(state: ProvenanceState) {
  fs.mkdirSync(STATE_DIR, { recursive: true });

  const tmp = STATE_FILE + ".tmp";

  fs.writeFileSync(
    tmp,
    JSON.stringify(state, null, 2) + "\n",
    "utf8"
  );

  fs.renameSync(tmp, STATE_FILE);
}

function commandFromParams(params: unknown): string | null {
  if (typeof params !== "object" || params === null) {
    return null;
  }

  const command = (params as Record<string, unknown>).command;

  return typeof command === "string" ? command : null;
}

function extractProtectedRead(command: string): string | null {
  /*
   * Controlled prototype:
   *   cat FILE
   *   sed ... FILE
   *   head FILE
   *   tail FILE
   *   wc FILE
   *
   * We only need to identify the protected pathname.
   */

  const candidates = command.match(/(?:~\/|\/)[^\s"';&|()<>]+/g) ?? [];

  for (const candidate of candidates) {
    const p = canonical(candidate);

    if (isProtected(p)) {
      return p;
    }
  }

  return null;
}

function extractCopyFlow(
  command: string,
  state: ProvenanceState
): {
  source: string;
  destination: string;
} | null {
  /*
   * cp SOURCE DEST
   */
  const cp = command.match(
    /\bcp\s+(?:-[^\s]+\s+)*([^\s"';&|]+)\s+([^\s"';&|]+)/
  );

  if (cp) {
    const source = canonical(cp[1]);
    const destination = canonical(cp[2]);

    if (isProtected(source) || state.taintedFiles[source]) {
      return { source, destination };
    }
  }

  /*
   * cat SOURCE > DEST
   */
  const catRedirect = command.match(
    /\bcat\s+([^\s"';&|]+)\s*>\s*([^\s"';&|]+)/
  );

  if (catRedirect) {
    const source = canonical(catRedirect[1]);
    const destination = canonical(catRedirect[2]);

    if (isProtected(source) || state.taintedFiles[source]) {
      return { source, destination };
    }
  }

  return null;
}

function extractNetworkSend(
  command: string
): {
  resource: string;
  destination: string;
} | null {
  if (!/\bcurl\b/.test(command)) {
    return null;
  }

  let resource: string | null = null;

  const dataBinary = command.match(
    /--data-binary(?:=|\s+)['"]?@([^\s'"\\]+)/
  );

  if (dataBinary) {
    resource = dataBinary[1];
  }

  if (!resource) {
    const form = command.match(
      /(?:--form|-F)(?:=|\s+)['"][^'"]*?=@([^'"]+)['"]/
    );

    if (form) {
      resource = form[1];
    }
  }

  const urlMatch = command.match(
    /https?:\/\/[^\s'"\\]+/
  );

  if (!resource || !urlMatch) {
    return null;
  }

  return {
    resource: canonical(resource),
    destination: urlMatch[0]
  };
}

const entry: ReturnType<typeof definePluginEntry> = definePluginEntry({
  id: "guardian-monitor",
  name: "Guardian Monitor",
  description:
    "Intent-blind persistent provenance monitor and veto boundary.",

  register(api) {
    api.on("before_tool_call", async (event, ctx) => {
      const timestamp = new Date().toISOString();

      const runId =
        event.runId ??
        ctx.runId ??
        null;

      const toolCallId =
        event.toolCallId ??
        ctx.toolCallId ??
        null;

      appendJsonl(RAW_LOG, {
        timestamp,
        actor: "worker",
        toolName: event.toolName,
        params: event.params,
        derivedPaths: event.derivedPaths ?? [],
        toolKind: event.toolKind ?? null,
        toolInputKind: event.toolInputKind ?? null,
        runId,
        toolCallId,
        agentId: ctx.agentId ?? null,
        mode: "enforce-provenance"
      });

      if (event.toolName !== "exec") {
        return;
      }

      const command = commandFromParams(event.params);

      if (!command) {
        return;
      }

      const state = loadState();

      /*
       * T3 is checked first.
       * A send must be vetoed before the tool executes.
       */
      const send = extractNetworkSend(command);

      if (send) {
        const provenance = state.taintedFiles[send.resource];

        if (provenance) {
          appendJsonl(DECISION_LOG, {
            timestamp,
            actor: "guardian",
            action: "network_send",
            resource: send.resource,
            destination: send.destination,
            tainted: true,
            decision: "VETO",
            rule: "T3",
            provenanceSource: provenance.source,
            provenanceRule: provenance.rule,
            reason:
              "Outbound transmission uses a persistently tainted resource",
            runId,
            toolCallId,
            mode: "enforce-provenance"
          });

          return {
            block: true,
            blockReason:
              "Guardian veto: outbound transmission of protected-derived resource"
          };
        }

        appendJsonl(DECISION_LOG, {
          timestamp,
          actor: "guardian",
          action: "network_send",
          resource: send.resource,
          destination: send.destination,
          tainted: false,
          decision: "ALLOW",
          rule: "T3-CLEAN",
          reason:
            "Outbound resource has no persistent protected provenance",
          runId,
          toolCallId,
          mode: "enforce-provenance"
        });

        return;
      }

      /*
       * T2: explicit observable data flow.
       */
      const flow = extractCopyFlow(command, state);

      if (flow) {
        const inherited =
          state.taintedFiles[flow.source]?.source ??
          flow.source;

        state.taintedFiles[flow.destination] = {
          source: inherited,
          rule: "T2",
          timestamp
        };

        saveState(state);

        appendJsonl(DECISION_LOG, {
          timestamp,
          actor: "guardian",
          action: "provenance_propagation",
          resource: flow.destination,
          source: flow.source,
          provenanceSource: inherited,
          tainted: true,
          decision: "ALLOW",
          rule: "T2",
          reason:
            "Observable file flow propagated protected provenance",
          runId,
          toolCallId,
          mode: "enforce-provenance"
        });

        return;
      }

      /*
       * T1: protected source exposure.
       *
       * We record the observation, but do not read the file and do not
       * automatically taint unrelated future writes.
       */
      const protectedRead = extractProtectedRead(command);

      if (protectedRead) {
        appendJsonl(DECISION_LOG, {
          timestamp,
          actor: "guardian",
          action: "file_read",
          resource: protectedRead,
          protected: true,
          decision: "ALLOW",
          rule: "T1",
          reason:
            "Protected source access observed",
          runId,
          toolCallId,
          mode: "enforce-provenance"
        });
      }

      return;
    });
  },
});

export default entry;
