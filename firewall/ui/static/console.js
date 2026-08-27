/* ==========================================================================
   Agent Firewall console client.
   Vanilla ES2020. No dependencies, no build step.

   This file renders. It does not decide. Every verdict, reason, and phase
   status shown here comes from the server, which gets it from the real
   FirewallSDK pipeline. Nothing is recomputed client-side.
   ========================================================================== */

"use strict";

/* --------------------------------------------------------------------------
   DOM helpers. Server data is always inserted as text, never as markup.
   -------------------------------------------------------------------------- */

const bind = (name) =>
  document.querySelector(`[data-bind="${name}"]`);

function h(tag, attrs, ...kids) {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else node.setAttribute(key, String(value));
  }

  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }

  return node;
}

const fill = (slot, ...kids) => {
  slot.replaceChildren(...kids.flat().filter(Boolean));
};

const empty = (message) => h("p", { class: "empty", text: message });

/* --------------------------------------------------------------------------
   Formatting
   -------------------------------------------------------------------------- */

const DASH = "\u2014";

function text(value, fallback = DASH) {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function clock(epoch) {
  if (typeof epoch !== "number" || !Number.isFinite(epoch)) return DASH;
  const d = new Date(epoch * 1000);
  const pad = (n, w = 2) => String(n).padStart(w, "0");
  return (
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` +
    `.${pad(d.getMilliseconds(), 3)}`
  );
}

/** Relative validity, e.g. "+59m" or "expired 2m ago". */
function relative(epoch) {
  if (typeof epoch !== "number" || !Number.isFinite(epoch)) return "";
  const delta = epoch * 1000 - Date.now();
  const abs = Math.abs(delta);
  const unit =
    abs < 60_000
      ? `${Math.round(abs / 1000)}s`
      : abs < 3_600_000
        ? `${Math.round(abs / 60_000)}m`
        : abs < 86_400_000
          ? `${Math.round(abs / 3_600_000)}h`
          : `${Math.round(abs / 86_400_000)}d`;
  return delta >= 0 ? `+${unit}` : `${unit} ago`;
}

function compact(value) {
  if (value === null || value === undefined) return DASH;
  if (typeof value === "object" && !Object.keys(value).length) return "{}";
  return JSON.stringify(value);
}

const slug = (value) => String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-");

/** Tokenize JSON for readability. Built as nodes, so no markup injection. */
function highlightJson(source) {
  const frag = document.createDocumentFragment();
  const re =
    /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

  let cursor = 0;
  let match;

  while ((match = re.exec(source)) !== null) {
    if (match.index > cursor) frag.append(source.slice(cursor, match.index));

    if (match[1] !== undefined) {
      frag.append(h("span", { class: match[2] ? "k" : "s", text: match[1] }));
      if (match[2]) frag.append(match[2]);
    } else if (match[3] !== undefined) {
      frag.append(h("span", { class: "b", text: match[3] }));
    } else {
      frag.append(h("span", { class: "n", text: match[4] }));
    }

    cursor = re.lastIndex;
  }

  frag.append(source.slice(cursor));
  return frag;
}

/* --------------------------------------------------------------------------
   Transport
   -------------------------------------------------------------------------- */

async function api(path, options) {
  const response = await fetch(path, options);
  let payload = null;

  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const detail = payload && payload.error ? payload.error : response.statusText;
    throw new Error(detail || `request failed: ${response.status}`);
  }

  return payload;
}

const evaluateScenario = (id) =>
  api("/api/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario: id }),
  });

/* --------------------------------------------------------------------------
   State
   -------------------------------------------------------------------------- */

const state = {
  system: null,
  scenarios: [],
  canEvaluate: false,
  selected: null,
  busy: false,
  trace: null,
};

/* --------------------------------------------------------------------------
   Pipeline
   -------------------------------------------------------------------------- */

const STATUS_LABEL = {
  passed: "passed",
  denied: "denied",
  not_reached: "not reached",
  unknown: "unknown",
};

function renderPipeline(nodes, { animate = false } = {}) {
  const list = bind("pipeline");

  list.classList.remove("pipeline--run");
  if (animate) void list.offsetWidth; // restart the stagger

  fill(
    list,
    (nodes || []).map((node, index) => {
      const status = node.status || null;

      return h(
        "li",
        {
          class: `node${node.kind === "terminal" ? " node--terminal" : ""}`,
          "data-status": status,
          "data-gate": node.id,
          style: `--i:${index}`,
        },
        h("span", { class: "node__idx", text: String(index).padStart(2, "0") }),
        h("span", { class: "node__rail" }, h("span", { class: "node__dot" })),
        h(
          "div",
          { class: "node__body" },
          h(
            "div",
            { class: "node__label" },
            h("span", { class: "node__name", text: node.label }),
            node.kind === "gate"
              ? h("code", { class: "node__gate", text: node.id })
              : null,
            h("span", {
              class: "node__status",
              text: status ? STATUS_LABEL[status] || status : "idle",
            }),
          ),
          node.summary ? h("p", { class: "node__summary", text: node.summary }) : null,
        ),
      );
    }),
  );

  if (animate) list.classList.add("pipeline--run");
}

function gateLabel(gateId) {
  const nodes = (state.system && state.system.pipeline) || [];
  const hit = nodes.find((node) => node.id === gateId);
  return hit ? hit.label : gateId;
}

function renderAttribution(result) {
  const slot = bind("attributionNote");

  if (!result) {
    slot.textContent =
      "Select an authorization request to trace it through the live pipeline.";
    return;
  }

  if (result.decision.allowed) {
    slot.textContent = "Every gate passed. Decision returned by the transaction gate.";
    return;
  }

  if (!result.attributed_phase) {
    slot.textContent =
      "This reason is not attributable to a single gate, so no gate is blamed " +
      "\u2014 the intermediate gates are reported as unknown rather than guessed.";
    return;
  }

  fill(
    slot,
    "Denied at ",
    h("strong", { text: gateLabel(result.attributed_phase) }),
    " \u2014 ",
    h("code", { text: result.attributed_phase }),
    ". Later gates were never reached.",
  );
}

/* --------------------------------------------------------------------------
   Decision
   -------------------------------------------------------------------------- */

function renderDecision(result) {
  const panel = bind("decisionPanel");
  const phaseChip = bind("decisionPhase");

  if (!result) {
    panel.dataset.state = "idle";
    bind("verdictGlyph").textContent = "";
    bind("verdictState").textContent = "awaiting request";
    bind("verdictReason").textContent = DASH;
    phaseChip.textContent = DASH;
    fill(bind("decisionFields"));
    fill(bind("decisionMetadata"));
    fill(bind("expectation"));
    return;
  }

  const decision = result.decision;
  const allowed = decision.allowed === true;

  panel.dataset.state = allowed ? "allow" : "deny";
  bind("verdictGlyph").textContent = allowed ? "\u2713" : "\u2715";
  bind("verdictState").textContent = allowed ? "ALLOW" : "DENY";
  bind("verdictReason").textContent = text(decision.reason);

  phaseChip.textContent = result.attributed_phase
    ? gateLabel(result.attributed_phase)
    : allowed
      ? "Security Transaction"
      : "unattributed";

  const rows = [
    ["agent", decision.agent],
    ["action", decision.action],
    ["tool", decision.tool],
    ["capability", decision.capability_id],
    ["request", compact(result.request && result.request.payload)],
  ];

  fill(
    bind("decisionFields"),
    rows.flatMap(([key, value]) => [
      h("dt", { text: key }),
      h("dd", {
        class: value === null || value === undefined ? "null" : null,
        text: text(value, "null"),
      }),
    ]),
  );

  const metadata = decision.metadata;

  fill(
    bind("decisionMetadata"),
    metadata
      ? Object.entries(metadata).map(([key, value]) =>
          h("span", {
            class: `tag${key === "delegation_depth" ? " tag--accent" : ""}`,
            text: `${key} = ${value}`,
          }),
        )
      : [h("span", { class: "tag", text: "metadata: none" })],
  );

  renderContext(result);
}

/** Expectation, prior requests, and scenario notes. */
function renderContext(result) {
  const slot = bind("expectation");
  const expectation = result.expectation;
  const parts = [];

  // Demo scenarios carry a documented expectation to compare against.
  // Ad-hoc control-plane requests do not, and inventing one would be a
  // claim the console cannot make, so the line is simply omitted.
  if (expectation) {
    parts.push(
      h(
        "div",
        { class: expectation.matches ? "expectation--ok" : "expectation--warn" },
        expectation.matches
          ? `Reason matches the documented expectation (${expectation.expects}).`
          : `Reason "${text(expectation.actual)}" differs from the documented ` +
            `expectation "${text(expectation.expects)}".`,
      ),
    );
  }

  if (result.warmup && result.warmup.length) {
    parts.push(
      h(
        "div",
        { class: "metaline" },
        result.warmup.map((prior) =>
          h("span", {
            class: "tag",
            text: `prior \u00b7 ${prior.action} \u2192 ${text(prior.reason)}`,
          }),
        ),
      ),
    );
  }

  for (const note of result.notes || []) {
    parts.push(h("p", { class: "panel__sub", text: note }));
  }

  fill(slot, parts);
}

/* --------------------------------------------------------------------------
   Delegation authority
   -------------------------------------------------------------------------- */

function renderAuthority(authority) {
  const slot = bind("chain");
  const chip = bind("chainDepth");

  if (!authority) {
    chip.textContent = DASH;
    fill(slot, empty("No capability presented, so no lineage to resolve."));
    return;
  }

  if (!authority.resolved) {
    chip.textContent = "unresolved";
    fill(
      slot,
      h(
        "div",
        { class: "chain__error" },
        "Lineage could not be resolved. Reported as an error, never as an ",
        "authorization outcome.",
        h("br"),
        h("code", {
          text: `${text(authority.error_type)}: ${text(authority.error)}`,
        }),
      ),
    );
    return;
  }

  const ceiling =
    authority.max_depth === null || authority.max_depth === undefined
      ? "unbounded"
      : authority.max_depth;

  chip.textContent = `depth ${authority.depth} / ${ceiling}`;

  fill(
    slot,
    (authority.links || []).map((link) =>
      h(
        "div",
        {
          class: "link",
          "data-role": link.role,
          "data-revoked": String(Boolean(link.effectively_revoked)),
        },
        h("span", { class: "link__rail" }, h("span", { class: "link__node" })),
        h(
          "div",
          { class: "link__main" },
          h("span", { class: "link__agent", text: text(link.agent_id) }),
          h("code", {
            class: "link__fp",
            text: `${text(link.fingerprint_short)}\u2026 \u00b7 ${text(link.capability)}`,
          }),
          h(
            "div",
            { class: "link__meta" },
            link.tool ? h("span", { class: "tag", text: `tool: ${link.tool}` }) : null,
            Object.keys(link.constraints || {}).length
              ? h("span", { class: "tag", text: `constraints: ${compact(link.constraints)}` })
              : null,
            link.revoked ? h("span", { class: "tag", text: "revoked" }) : null,
            link.effectively_revoked && !link.revoked
              ? h("span", { class: "tag", text: "revoked via ancestor" })
              : null,
          ),
        ),
        h("span", { class: "link__role", text: link.role }),
      ),
    ),
  );
}

/* --------------------------------------------------------------------------
   Posture
   -------------------------------------------------------------------------- */

const RISK_FILL = { NORMAL: 25, ELEVATED: 58, RESTRICTED: 82, REVOKED: 100 };

function renderPosture(posture) {
  const slot = bind("posture");

  if (!posture) {
    fill(slot, empty("No posture data."));
    return;
  }

  const meters = (posture.risk || []).map((row) =>
    h(
      "div",
      { class: "meter", "data-level": row.level },
      h(
        "div",
        { class: "meter__top" },
        h("span", { class: "meter__agent", text: row.agent }),
        h("span", { class: "meter__level", text: row.level }),
      ),
      h(
        "div",
        { class: "meter__track" },
        h("div", {
          class: "meter__fill",
          style: `width:${RISK_FILL[row.level] || 25}%`,
        }),
      ),
      h("span", {
        class: "meter__counts",
        text:
          `${row.event_count} events \u00b7 ${row.denial_count} denials \u00b7 ` +
          `${row.escalation_count} escalations`,
      }),
    ),
  );

  const flag = (label, on, detail) =>
    h(
      "span",
      { class: "flag", "data-on": String(Boolean(on)) },
      h("i"),
      detail ? `${label}: ${detail}` : label,
    );

  const ceiling =
    posture.max_delegation_depth === null || posture.max_delegation_depth === undefined
      ? "unbounded"
      : posture.max_delegation_depth;

  fill(
    slot,
    meters.length
      ? h("div", { class: "posture__row" }, meters)
      : empty("Risk tracking " + (posture.risk_tracked ? "on, no agents observed yet." : "not configured.")),
    h(
      "div",
      { class: "flags" },
      flag("risk context", posture.risk_tracked),
      flag(
        "refusal memo",
        posture.refusal_active,
        posture.refusal_active ? `${text(posture.refusal_entries, "?")} entries` : null,
      ),
      flag("security context", posture.security_context_active),
      flag("semantic context", posture.semantic_context_active),
      flag("depth ceiling", posture.max_delegation_depth !== null, String(ceiling)),
    ),
  );
}

/* --------------------------------------------------------------------------
   Capabilities
   -------------------------------------------------------------------------- */

const CAP_COLUMNS = [
  "fingerprint",
  "agent",
  "capability",
  "tool",
  "issuer",
  "expires",
  "constraints",
  "revoked",
  "withheld",
];

function renderCapabilities(inventory) {
  const table = bind("capabilities");

  const head = h(
    "thead",
    {},
    h("tr", {}, CAP_COLUMNS.map((label) => h("th", { text: label }))),
  );

  if (!inventory || !inventory.length) {
    fill(
      table,
      head,
      h(
        "tbody",
        {},
        h(
          "tr",
          {},
          h("td", {
            class: "dim",
            colspan: String(CAP_COLUMNS.length),
            text: "No capabilities in this request.",
          }),
        ),
      ),
    );
    return;
  }

  fill(
    table,
    head,
    h(
      "tbody",
      {},
      inventory.map((cap) => {
        const revoked = Boolean(cap.revoked || cap.effectively_revoked);

        return h(
          "tr",
          {},
          h("td", { class: "strong", text: `${text(cap.fingerprint_short)}\u2026` }),
          h("td", { class: "strong", text: text(cap.agent_id) }),
          h("td", { text: text(cap.capability) }),
          h("td", { class: cap.tool ? null : "dim", text: text(cap.tool, "unbound") }),
          h("td", { text: text(cap.issuer) }),
          h(
            "td",
            {},
            clock(cap.expires_at),
            h("span", { class: "pill pill--no", text: relative(cap.expires_at) }),
          ),
          h("td", { class: "wrap", text: compact(cap.constraints) }),
          h(
            "td",
            {},
            h("span", {
              class: `pill ${revoked ? "pill--yes" : "pill--no"}`,
              text: cap.revoked
                ? "direct"
                : cap.effectively_revoked
                  ? "ancestor"
                  : "no",
            }),
          ),
          h("td", { class: "dim", text: (cap.redacted || []).join(", ") }),
        );
      }),
    ),
  );
}

/* --------------------------------------------------------------------------
   Lifecycle
   -------------------------------------------------------------------------- */

const EVENT_COLUMNS = [
  "time",
  "event",
  "agent",
  "capability",
  "reason",
  "fingerprint",
  "request",
];

function renderLifecycle(events, totals) {
  const table = bind("lifecycle");
  const totalsSlot = bind("lifecycleTotals");

  const entries = Object.entries(totals || {});

  fill(
    totalsSlot,
    entries.length
      ? entries.map(([key, count]) =>
          h("span", { class: `pill pill--${slug(key)}`, text: `${key} ${count}` }),
        )
      : [h("span", { class: "pill pill--no", text: "no events" })],
  );

  const head = h(
    "thead",
    {},
    h("tr", {}, EVENT_COLUMNS.map((label) => h("th", { text: label }))),
  );

  if (!events || !events.length) {
    fill(
      table,
      head,
      h(
        "tbody",
        {},
        h(
          "tr",
          {},
          h("td", {
            class: "dim",
            colspan: String(EVENT_COLUMNS.length),
            text: "No lifecycle events recorded.",
          }),
        ),
      ),
    );
    return;
  }

  fill(
    table,
    head,
    h(
      "tbody",
      {},
      events.map((event) =>
        h(
          "tr",
          {},
          h("td", { class: "dim", text: clock(event.timestamp) }),
          h(
            "td",
            {},
            h("span", {
              class: `pill pill--${slug(event.event_type)}`,
              text: text(event.event_type),
            }),
          ),
          h("td", { class: "strong", text: text(event.agent_id) }),
          h("td", { text: text(event.capability) }),
          h("td", { class: "wrap", text: text(event.reason, "") || DASH }),
          h("td", { class: "dim", text: `${text(event.fingerprint_short)}\u2026` }),
          h("td", { class: "dim", text: text(event.request_id, "") || DASH }),
        ),
      ),
    ),
  );
}

/* --------------------------------------------------------------------------
   Trace
   -------------------------------------------------------------------------- */

function renderTrace(result) {
  const slot = bind("trace");

  if (!result) {
    state.trace = null;
    slot.textContent = DASH;
    return;
  }

  const payload = {
    scenario: result.scenario,
    request: result.request,
    decision: result.decision,
    attributed_phase: result.attributed_phase,
    phases: (result.phases || []).map((node) => ({
      index: node.index,
      id: node.id,
      status: node.status,
    })),
    delegation_authority: result.authority,
  };

  state.trace = JSON.stringify(payload, null, 2);
  slot.replaceChildren(highlightJson(state.trace));
}

/* --------------------------------------------------------------------------
   Scenario navigation
   -------------------------------------------------------------------------- */

const GROUP_LABEL = { allow: "Expected allow", deny: "Expected deny" };

function renderScenarios() {
  const nav = bind("scenarios");
  const groups = new Map();

  for (const scenario of state.scenarios) {
    if (!groups.has(scenario.group)) groups.set(scenario.group, []);
    groups.get(scenario.group).push(scenario);
  }

  fill(
    nav,
    [...groups.entries()].map(([group, items]) =>
      h(
        "div",
        { class: "scen-group" },
        h("div", {
          class: "scen-group__label",
          text: GROUP_LABEL[group] || group,
        }),
        items.map((scenario) =>
          h(
            "button",
            {
              class: "scen",
              type: "button",
              "data-scenario": scenario.id,
              "data-group": scenario.group,
              "aria-current": String(state.selected === scenario.id),
              disabled: !state.canEvaluate,
              title: scenario.intent,
            },
            h("span", { class: "scen__title" }, h("i"), scenario.title),
            h("span", { class: "scen__reason", text: scenario.expects }),
          ),
        ),
      ),
    ),
  );

  bind("scenarioCount").textContent = String(state.scenarios.length);
}

async function select(id) {
  if (!id || state.busy || !state.canEvaluate) return;

  state.busy = true;
  state.selected = id;
  renderScenarios();

  const main = document.querySelector(".main");
  main.classList.add("is-busy");

  try {
    const result = await evaluateScenario(id);

    renderPipeline(result.phases, { animate: true });
    renderAttribution(result);
    renderDecision(result);
    renderAuthority(result.authority);
    renderPosture(result.posture);
    renderCapabilities(result.inventory);
    renderLifecycle(result.lifecycle, countEvents(result.lifecycle));
    renderTrace(result);
  } catch (error) {
    bind("attributionNote").textContent = `Evaluation failed: ${error.message}`;
  } finally {
    main.classList.remove("is-busy");
    state.busy = false;
  }
}

function countEvents(events) {
  const totals = {};
  for (const event of events || []) {
    totals[event.event_type] = (totals[event.event_type] || 0) + 1;
  }
  return totals;
}

/* --------------------------------------------------------------------------
   Boot
   -------------------------------------------------------------------------- */

function renderSystem(system) {
  bind("version").textContent = text(system.version);
  bind("depthPolicy").textContent =
    system.max_delegation_depth === null || system.max_delegation_depth === undefined
      ? "unbounded"
      : String(system.max_delegation_depth);
  bind("decisionSource").textContent = text(system.decision_source);
  bind("decisionSourceInline").textContent = text(system.decision_source);
  bind("mode").textContent = `mode: ${text(system.mode)}`;
}

async function boot() {
  renderDecision(null);
  renderAttribution(null);
  renderAuthority(null);
  renderCapabilities(null);
  renderLifecycle(null, null);
  renderTrace(null);

  try {
    const [system, catalog] = await Promise.all([
      api("/api/system"),
      api("/api/scenarios"),
    ]);

    state.system = system;
    state.scenarios = catalog.scenarios || [];
    state.canEvaluate = Boolean(system.can_evaluate && catalog.can_evaluate);

    renderSystem(system);
    renderPipeline(system.pipeline);
    renderScenarios();

    if (state.canEvaluate) {
      bind("scenarioNote").textContent =
        "Demo requests, evaluated by the real authorization pipeline in a " +
        "disposable workspace.";
      await select(state.scenarios[0] && state.scenarios[0].id);
    } else {
      bind("scenarioNote").textContent =
        "Attached to a live FirewallSDK. Evaluation is disabled here because " +
        "authorizing has real security side effects; the panels below read " +
        "live state instead.";
      await loadAttached();
    }
  } catch (error) {
    bind("attributionNote").textContent = `Console unavailable: ${error.message}`;
  }
}

async function loadAttached() {
  const [posture, lifecycle] = await Promise.all([
    api("/api/posture"),
    api("/api/lifecycle"),
  ]);

  renderPosture(posture.posture);
  renderLifecycle(lifecycle.events, posture.lifecycle_totals);
}

/* --- events --- */

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-scenario]");
  if (button) {
    select(button.dataset.scenario);
    return;
  }

  if (event.target.closest('[data-bind="copyTrace"]')) copyTrace(event.target);
});

async function copyTrace(button) {
  if (!state.trace) return;

  try {
    await navigator.clipboard.writeText(state.trace);
    button.textContent = "copied";
  } catch {
    button.textContent = "copy failed";
  }

  setTimeout(() => {
    button.textContent = "copy";
  }, 1400);
}

/* Arrow-key movement through the request list. */
bind("scenarios").addEventListener("keydown", (event) => {
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;

  const buttons = [...bind("scenarios").querySelectorAll("[data-scenario]")];
  const index = buttons.indexOf(document.activeElement);
  if (index === -1) return;

  event.preventDefault();
  const next = buttons[index + (event.key === "ArrowDown" ? 1 : -1)];
  if (next) next.focus();
});

boot();
