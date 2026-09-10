/* ==========================================================================
   Agent Firewall v1.8 -- Security Flight Recorder console panel.

   Renders the recorder projection served by GET /api/recorder:

     - verification status (verified / failed / unverifiable / incomplete /
       redacted), never conflated
     - the agent security timeline (chronological, every entry inspectable)
     - the security trajectory (evidence-backed posture transitions)
     - the derived security graph (why-can / reachable)
     - containment state (read-only here; mutations go through the
       control plane)
     - the counterfactual replay laboratory (POST /api/control/replay)

   This file renders. It does not decide, and it never recomputes
   security state client-side: everything shown comes from the server
   projections, which derive from recorded events only.
   ========================================================================== */

"use strict";

(function () {
  // ----------------------------------------------------------------
  // DOM helpers (kept local; console.js has its own copy)
  // ----------------------------------------------------------------

  const bind = (name) => document.querySelector(`[data-bind="${name}"]`);

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

  function clock(epoch) {
    if (typeof epoch !== "number" || !Number.isFinite(epoch)) return "\u2014";
    const d = new Date(epoch * 1000);
    const pad = (n, w = 2) => String(n).padStart(w, "0");
    return (
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` +
      `.${pad(d.getMilliseconds(), 3)}`
    );
  }

  function compact(value) {
    if (value === null || value === undefined) return "\u2014";
    if (typeof value === "object" && !Object.keys(value).length) return "{}";
    return JSON.stringify(value);
  }

  const STATUS_META = {
    verified: { label: "verified", cls: "ok" },
    redacted: { label: "redacted", cls: "warn" },
    incomplete: { label: "incomplete", cls: "warn" },
    failed: { label: "failed", cls: "bad" },
    unverifiable: { label: "unverifiable", cls: "bad" },
  };

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

  // ----------------------------------------------------------------
  // Verification
  // ----------------------------------------------------------------

  function renderVerification(view) {
    const slot = bind("recorderVerify");
    const meta = STATUS_META[view.status] || { label: view.status, cls: "warn" };

    const findings = (view.findings || []).map((finding) =>
      h(
        "div",
        { class: `finding finding--${finding.severity}` },
        h("span", { class: "finding__code", text: finding.code }),
        h("span", { class: "finding__msg", text: finding.message }),
      ),
    );

    fill(
      slot,
      h(
        "div",
        { class: "verify-banner", "data-status": view.status },
        h("span", { class: `pill pill--${meta.cls}`, text: meta.label }),
        h("span", { class: "verify-banner__summary", text: view.summary ? view.summary.session_id : "" }),
      ),
      findings.length ? h("div", { class: "findings" }, findings) : null,
    );
  }

  // ----------------------------------------------------------------
  // Timeline
  // ----------------------------------------------------------------

  function renderTimeline(entries) {
    const slot = bind("recorderTimeline");

    if (!entries || !entries.length) {
      fill(slot, h("p", { class: "empty", text: "No recorded events." }));
      return;
    }

    fill(
      slot,
      entries.map((entry) =>
        h(
          "div",
          { class: "tl-row", "data-sev": entry.severity, "data-kind": entry.kind },
          h("span", { class: "tl-row__time", text: clock(entry.timestamp) }),
          h("span", { class: "tl-row__dot" }),
          h(
            "div",
            { class: "tl-row__body" },
            h("div", { class: "tl-row__head" },
              h("span", { class: "tl-row__title", text: entry.title }),
              h("span", { class: "tag", text: entry.event_type }),
            ),
            h("p", { class: "tl-row__detail", text: entry.detail }),
            h("div", { class: "tl-row__meta" },
              h("span", { class: "tag", text: `#${entry.seq}` }),
              entry.agent ? h("span", { class: "tag", text: entry.agent }) : null,
            ),
          ),
        ),
      ),
    );
  }

  // ----------------------------------------------------------------
  // Trajectory
  // ----------------------------------------------------------------

  function renderTrajectory(trajectory) {
    const slot = bind("recorderTrajectory");

    if (!trajectory || !trajectory.transitions.length) {
      fill(slot, h("p", { class: "empty", text: "No posture transitions recorded." }));
      return;
    }

    const steps = [["trusted", 0], ["unusual", 1], ["suspicious", 2],
                   ["high_risk", 3], ["contained", 4], ["recovered", 5]];

    const ladder = h("div", { class: "ladder" },
      steps.map(([posture]) =>
        h("span", { class: "ladder__step", "data-posture": posture, text: posture }),
      ),
    );

    const transitions = trajectory.transitions.map((transition) =>
      h(
        "div",
        { class: "traj-row" },
        h("span", { class: "traj-row__time", text: clock(transition.timestamp) }),
        h(
          "span",
          { class: "traj-row__arrow", text: `${transition.from} \u2192 ${transition.to}` },
        ),
        h(
          "div",
          { class: "traj-row__signals" },
          (transition.signals || []).map((signal) =>
            h("p", { class: "traj-row__signal",
                text: `evidence #${signal.evidence_seq}: ${signal.description}` }),
          ),
        ),
      ),
    );

    fill(slot, ladder, transitions);
  }

  // ----------------------------------------------------------------
  // Graph
  // ----------------------------------------------------------------

  function renderGraph(graph) {
    const slot = bind("recorderGraph");

    if (!graph || !graph.nodes || !graph.nodes.length) {
      fill(slot, h("p", { class: "empty", text: "No graph data." }));
      return;
    }

    const byType = {};
    for (const node of graph.nodes) {
      (byType[node.type] = byType[node.type] || []).push(node.label);
    }

    const nodeTypeOrder = ["agent", "capability", "issuer", "tool", "policy", "session", "resource"];

    const legend = h("div", { class: "graph-legend" },
      nodeTypeOrder
        .filter((type) => byType[type] && byType[type].length)
        .map((type) =>
          h("span", { class: "tag", text: `${type}: ${byType[type].length}` }),
        ),
    );

    const edgeTypes = {};
    for (const edge of graph.edges || []) {
      edgeTypes[edge.type] = (edgeTypes[edge.type] || 0) + 1;
    }

    const edges = h("div", { class: "graph-edges" },
      Object.entries(edgeTypes).map(([type, count]) =>
        h("span", { class: "tag", text: `${type} ${count}` }),
      ),
    );

    const agents = byType.agent || [];
    const caps = byType.capability || [];

    const why = h("div", { class: "graph-why" },
      agents.map((agent) =>
        h(
          "details",
          { class: "graph-why__agent" },
          h("summary", { text: `why can ${agent}?` }),
          h("p", { class: "panel__sub", text: "Ask per action with the CLI: firewall graph session.afw --agent " + agent + " --why <action>" }),
        ),
      ),
    );

    fill(
      slot,
      h("p", { class: "panel__sub", text: `${graph.nodes.length} nodes, ${(graph.edges || []).length} edges -- derived from recorded events.` }),
      legend,
      edges,
      why,
    );

    // The full node/edge list is available for inspection.
    const details = h("details", { class: "graph-dump" },
      h("summary", { text: "inspect nodes & edges" }),
      h("pre", { class: "code code--scroll", text: JSON.stringify(graph, null, 2) }),
    );
    slot.append(details);
  }

  // ----------------------------------------------------------------
  // Containment
  // ----------------------------------------------------------------

  function renderContainment(containment) {
    const slot = bind("recorderContainment");

    if (!containment) {
      fill(slot, h("p", { class: "empty", text: "No containment state." }));
      return;
    }

    const states = Object.entries(containment.states || {});

    const rows = states.map(([agent, state]) =>
      h("div", { class: "cont-row", "data-state": state },
        h("span", { class: "cont-row__agent", text: agent }),
        h("span", { class: `pill pill--${state}`, text: state }),
      ),
    );

    const history = (containment.history || []).map((event) =>
      h("div", { class: "cont-event" },
        h("span", { class: "tag", text: clock(event.timestamp) }),
        h("span", { class: "cont-event__action", text: `${event.action} ${event.from} \u2192 ${event.to}` }),
        h("span", { class: "tag", text: `actor: ${event.actor}` }),
        h("span", { class: "tag", text: event.reason }),
      ),
    );

    fill(
      slot,
      states.length
        ? h("div", { class: "cont-states" }, rows)
        : h("p", { class: "empty", text: "All agents active." }),
      history.length ? h("div", { class: "cont-history" }, history) : null,
    );
  }

  // ----------------------------------------------------------------
  // Counterfactual replay
  // ----------------------------------------------------------------

  async function runReplay(payload) {
    const slot = bind("recorderReplayResult");
    fill(slot, h("p", { class: "empty", text: "Replaying\u2026" }));

    try {
      const report = await api("/api/replay", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload || {}),
      });

      const summary = report.summary || {};
      const rows = (report.rows || []).map((row) =>
        h(
          "tr",
          { "data-class": row.classification },
          h("td", { text: row.seq }),
          h("td", { text: row.agent }),
          h("td", { text: row.action }),
          h("td", {
            text: row.observed && row.observed.allowed !== null
              ? (row.observed.allowed ? "ALLOWED" : "DENIED") + " (" + row.observed.reason + ")"
              : "\u2014",
          }),
          h("td", {
            text: row.counterfactual && row.counterfactual.allowed !== null
              ? (row.counterfactual.allowed ? "ALLOWED" : "DENIED") + " (" + row.counterfactual.reason + ")"
              : "\u2014",
          }),
          h("td", { text: row.classification }),
        ),
      );

      fill(
        slot,
        h("div", { class: "sim__grid" },
          h("div", { class: "sim__stat" },
            h("span", { class: "stat__key", text: "newly denied" }),
            h("span", { class: "stat__val", text: summary.newly_denied })),
          h("div", { class: "sim__stat" },
            h("span", { class: "stat__key", text: "newly allowed" }),
            h("span", { class: "stat__val", text: summary.newly_allowed })),
          h("div", { class: "sim__stat" },
            h("span", { class: "stat__key", text: "verified" }),
            h("span", { class: "stat__val", text: summary.verified })),
          h("div", { class: "sim__stat" },
            h("span", { class: "stat__key", text: "unverifiable" }),
            h("span", { class: "stat__val", text: summary.unverifiable })),
        ),
        rows.length
          ? h("div", { class: "tablewrap" },
              h("table", { class: "table" },
                h("thead", {}, h("tr", {},
                  ["seq", "agent", "action", "observed", "counterfactual", "class"].map((c) => h("th", { text: c })))),
                h("tbody", {}, rows),
              ),
            )
          : h("p", { class: "empty", text: "No replayable decisions in this session." }),
      );
    } catch (error) {
      fill(slot, h("p", { class: "empty", text: `Replay failed: ${error.message}` }));
    }
  }

  function wireReplay() {
    const form = bind("recorderReplayForm");
    if (!form) return;

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const depth = bind("recorderReplayDepth").value;
      const issuers = bind("recorderReplayIssuers").value;

      const payload = {};
      if (depth !== "") payload.max_delegation_depth = Number(depth);
      if (issuers.trim() !== "") {
        payload.trusted_issuers = issuers.split(",").map((s) => s.trim()).filter(Boolean);
      }

      runReplay(payload);
    });

    // Show the baseline immediately.
    runReplay({});
  }

  // ----------------------------------------------------------------
  // Boot
  // ----------------------------------------------------------------

  async function loadRecorder() {
    try {
      const view = await api("/api/recorder");

      if (!view.available) {
        fill(bind("recorderPanel"), h("p", { class: "empty", text: view.reason || "recorder unavailable" }));
        return;
      }

      const session = view.session || {};

      fill(bind("recorderSession"),
        h("span", { class: "tag", text: `session ${session.id}` }),
        h("span", { class: "tag", text: `agent ${session.agent || "\u2014"}` }),
        h("span", { class: "tag", text: `${session.event_count} events` }),
        h("span", { class: "tag", text: `${session.checkpoint_count} checkpoints` }),
      );

      renderVerification(view.verification);
      renderTimeline(view.timeline);
      renderTrajectory(view.trajectory);
      renderGraph(view.graph);
      renderContainment(view.containment);
      wireReplay();
    } catch (error) {
      fill(bind("recorderPanel"), h("p", { class: "empty", text: `Recorder unavailable: ${error.message}` }));
    }
  }

  document.addEventListener("DOMContentLoaded", loadRecorder);
})();
