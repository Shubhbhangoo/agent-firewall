/* ==========================================================================
   Agent Firewall v1.9 -- Security Operations Center panel.

   Renders the SOC projection served by GET /api/soc:

     - active agents with reachable capabilities/tools/resources
     - behavioral detections (what/why/evidence/severity/response)
     - correlation bundles across artifacts
     - sensitive resources (attack-path summary)
     - attack-path queries (POST /api/soc/attack-paths)
     - scenario simulation (POST /api/soc/simulate)

   Response automation (POST /api/control/respond) goes through the
   control plane's bearer-token gate.

   This file renders. It never recomputes security state client-side.
   ========================================================================== */

"use strict";

(function () {
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
  // Agents
  // ----------------------------------------------------------------

  function renderAgents(agents) {
    const slot = bind("socAgents");
    const list = Object.values(agents || {});

    if (!list.length) {
      fill(slot, h("p", { class: "empty", text: "No agents in the network." }));
      return;
    }

    fill(
      slot,
      list.map((entry) => {
        const reach = entry.reachable || {};
        const detections = entry.detections || [];
        const maxSeverity = detections.reduce((worst, d) => {
          const rank = { low: 1, medium: 2, high: 3, critical: 4 };
          return Math.max(worst, rank[d.severity] || 0);
        }, 0);

        return h(
          "div",
          { class: "soc-agent", "data-risk": maxSeverity },
          h("div", { class: "soc-agent__head" },
            h("span", { class: "soc-agent__name", text: entry.agent }),
            h("span", {
              class: "pill pill--" + (maxSeverity >= 3 ? "quarantined" : maxSeverity === 2 ? "restricted" : "active"),
              text: detections.length ? `${detections.length} detection(s)` : "clear",
            }),
          ),
          h("div", { class: "soc-agent__reach" },
            reach.capabilities && reach.capabilities.length
              ? h("p", { class: "soc-agent__line", text: "capabilities: " + reach.capabilities.join(", ") })
              : null,
            reach.tools && reach.tools.length
              ? h("p", { class: "soc-agent__line", text: "tools: " + reach.tools.join(", ") })
              : null,
            reach.resources && reach.resources.length
              ? h("p", { class: "soc-agent__line soc-agent__line--warn", text: "resources: " + reach.resources.join(", ") })
              : null,
          ),
          detections.length
            ? h("div", { class: "soc-agent__dets" },
                detections.map((det) =>
                  h("p", { class: "soc-agent__det", text: `[${det.severity}] ${det.title}` }),
                ),
              )
            : null,
        );
      }),
    );
  }

  // ----------------------------------------------------------------
  // Detections
  // ----------------------------------------------------------------

  function renderDetections(detections) {
    const slot = bind("socDetections");

    if (!detections || !detections.length) {
      fill(slot, h("p", { class: "empty", text: "No behavioral detections." }));
      return;
    }

    fill(
      slot,
      detections.map((det) =>
        h(
          "div",
          { class: "det", "data-severity": det.severity },
          h("div", { class: "det__head" },
            h("span", { class: "det__sev", text: det.severity }),
            h("span", { class: "det__title", text: det.title }),
            h("span", { class: "tag", text: det.rule_id }),
          ),
          h("p", { class: "det__why", text: det.explanation }),
          h("p", { class: "det__meta", text: "agents: " + (det.agents || []).join(", ") }),
          det.evidence && det.evidence.length
            ? h("p", { class: "det__ev",
                text: "evidence: " +
                  det.evidence.map((e) => `${e.artifact}#${e.event_seq}`).join(", ") })
            : null,
          det.response
            ? h("p", { class: "det__resp", text: "recommended: " + det.response })
            : null,
        ),
      ),
    );
  }

  // ----------------------------------------------------------------
  // Bundles + sensitive resources
  // ----------------------------------------------------------------

  function renderBundles(bundles) {
    const slot = bind("socBundles");

    if (!bundles || !bundles.length) {
      fill(slot, h("p", { class: "empty", text: "No correlation bundles." }));
      return;
    }

    fill(
      slot,
      bundles.map((bundle) =>
        h("div", { class: "bundle" },
          h("span", { class: "bundle__id", text: bundle.bundle_id }),
          h("span", { class: "tag", text: bundle.reason }),
          h("span", { class: "tag", text: `${bundle.artifact_ids.length} artifact(s)` }),
        ),
      ),
    );
  }

  function renderSensitive(resources) {
    const slot = bind("socSensitive");

    if (!resources || !resources.length) {
      fill(slot, h("p", { class: "empty", text: "No sensitive resources recorded." }));
      return;
    }

    fill(
      slot,
      resources.map((entry) =>
        h("div", { class: "sensitive" },
          h("span", { class: "sensitive__name", text: entry.resource }),
          h("span", { class: "tag", text: `${entry.evidence.length} evidence` }),
        ),
      ),
    );
  }

  // ----------------------------------------------------------------
  // Attack paths
  // ----------------------------------------------------------------

  async function runAttackPath(payload) {
    const slot = bind("socAttackResult");
    fill(slot, h("p", { class: "empty", text: "Searching paths\u2026" }));

    try {
      const result = await api("/api/soc/attack-paths", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (result.path) {
        const path = result.path;
        const parts = [];

        if (!path) {
          fill(slot, h("p", { class: "empty", text: "No path found." }));
          return;
        }

        parts.push(h("p", { class: "soc-path__line",
          text: `${result.agent} -> ${result.target} [${path.status}] ` +
            (path.potentially_dangerous ? "DANGEROUS" : "") }));

        for (const hop of path.hops) {
          parts.push(h("p", { class: "soc-path__hop",
            text: `  ${hop.edge} -> ${hop.target} [${hop.status}]` }));
        }

        if (result.break_suggestions && result.break_suggestions.length) {
          parts.push(h("p", { class: "soc-path__break", text: "break the path:" }));
          for (const suggestion of result.break_suggestions.slice(0, 3)) {
            parts.push(h("p", { class: "soc-path__hop",
              text: `  ${suggestion.action} ${suggestion.capability} -- ${suggestion.effect}` }));
          }
        }

        fill(slot, parts);
        return;
      }

      const paths = result.paths || [];
      if (!paths.length) {
        fill(slot, h("p", { class: "empty", text: `No recorded paths to ${result.target}.` }));
        return;
      }

      fill(
        slot,
        h("p", { class: "soc-path__line", text: `${paths.length} path(s) to ${result.target}:` }),
        paths.slice(0, 8).map((path) =>
          h("p", { class: "soc-path__hop",
            text: `  ${path.source} (${path.hops.length} hops, ${path.status}` +
              (path.potentially_dangerous ? ", DANGEROUS" : "") + `)` }),
        ),
      );
    } catch (error) {
      fill(slot, h("p", { class: "empty", text: `Attack path failed: ${error.message}` }));
    }
  }

  function wireAttackPath() {
    const form = bind("socAttackForm");
    if (!form) return;

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const payload = {
        agent: bind("socAttackAgent").value || undefined,
        target: bind("socAttackTarget").value,
      };
      runAttackPath(payload);
    });
  }

  // ----------------------------------------------------------------
  // Scenario simulation
  // ----------------------------------------------------------------

  async function runSimulate(payload) {
    const slot = bind("socSimResult");
    fill(slot, h("p", { class: "empty", text: "Simulating\u2026" }));

    try {
      const report = await api("/api/soc/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const parts = [];
      parts.push(h("p", { class: "soc-path__line",
        text: `scenario: ${report.scenario.title} (${report.scenario.kind})` }));
      parts.push(h("p", { class: "soc-path__hop",
        text: "initial capabilities: " + (report.initial.capabilities || []).join(", ") }));

      for (const path of report.available_paths || []) {
        parts.push(h("p", { class: "soc-path__hop",
          text: `  path: ${path.source} -> ${path.target} [${path.status}]` }));
      }

      parts.push(h("p", { class: "soc-path__hop",
        text: "reachable resources: " + (report.reachable_resources || []).join(", ") }));

      for (const decision of report.policy_decisions || []) {
        parts.push(h("p", { class: "soc-path__hop",
          text: `  ${decision.action} -> ${decision.allowed ? "ALLOWED" : "DENIED"} (${decision.reason}) [${decision.basis}]` }));
      }

      for (const opportunity of report.containment_opportunities || []) {
        parts.push(h("p", { class: "soc-path__break", text: `containment: ${opportunity.action} -- ${opportunity.effect}` }));
      }

      fill(slot, parts);
    } catch (error) {
      fill(slot, h("p", { class: "empty", text: `Simulation failed: ${error.message}` }));
    }
  }

  function wireSimulate() {
    const form = bind("socSimForm");
    if (!form) return;

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const payload = {
        agent: bind("socSimAgent").value,
        kind: bind("socSimKind").value,
        title: bind("socSimTitle").value || "browser scenario",
        added_capabilities: bind("socSimAdded").value
          ? bind("socSimAdded").value.split(",").map((s) => s.trim()).filter(Boolean)
          : [],
        containment: bind("socSimContainment").value,
      };
      runSimulate(payload);
    });
  }

  // ----------------------------------------------------------------
  // Boot
  // ----------------------------------------------------------------

  async function loadSoc() {
    try {
      const view = await api("/api/soc");

      bind("socArtifacts").textContent =
        `verified artifacts: ${(view.verified_artifacts || []).join(", ") || "none"}`;

      renderAgents(view.agents);
      renderDetections(view.detections);
      renderBundles(view.bundles);
      renderSensitive(view.sensitive_resources);
      wireAttackPath();
      wireSimulate();
    } catch (error) {
      fill(bind("socPanel"), h("p", { class: "empty", text: `SOC unavailable: ${error.message}` }));
    }
  }

  document.addEventListener("DOMContentLoaded", loadSoc);
})();
