/* v2.1 Autonomous Defense panel - browser bindings.
   Read-only projections over the v2.1 subsystems. All analysis is
   labeled with its basis; nothing in this panel authorizes anything. */

(function () {
  "use strict";

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const key of Object.keys(attrs)) {
        if (key === "class") node.className = attrs[key];
        else if (key.startsWith("data-")) node.setAttribute(key, attrs[key]);
        else node[key] = attrs[key];
      }
    }
    (children || []).forEach((child) => {
      node.appendChild(
        typeof child === "string" ? document.createTextNode(child) : child
      );
    });
    return node;
  }

  function bind(target, fn) {
    if (!target) return;
    const value = fn();
    if (value && typeof value.then === "function") {
      value.then((result) => {
        target.replaceChildren(result);
      });
    } else {
      target.replaceChildren(value);
    }
  }

  async function api(path, payload) {
    const options = { method: "GET" };
    if (payload !== undefined) {
      options.method = "POST";
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify(payload);
    }
    const response = await fetch(path, options);
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || ("HTTP " + response.status));
    }
    return response.json();
  }

  const STATE_LABEL = {
    active: "active",
    restricted: "restricted",
    quarantined: "quarantined",
    recovering: "recovering",
    re_entering: "re-entering",
    retired: "retired",
  };

  const STATE_CLASS = {
    active: "v21__tag--active",
    restricted: "v21__tag--restricted",
    quarantined: "v21__tag--quarantined",
    recovering: "v21__tag--recovering",
    retired: "v21__tag--retired",
  };

  function renderMesh(data) {
    if (!data || !data.states || !data.states.length) {
      return el("p", { class: "v21__empty" }, ["no agents in the mesh"]);
    }
    const list = el("ul", { class: "v21__list" });
    data.states.forEach((state) => {
      const li = el("li", {}, [
        el("div", { class: "v21__evidence-row" }, [
          el("span", {}, [state.agent]),
          el("span", { class: "v21__tag " + (STATE_CLASS[state.state] || "") }, [
            STATE_LABEL[state.state] || state.state,
          ]),
        ]),
        el("div", { class: "v21__basis" }, [
          "identity=" + (state.identity_verified ? "ok" : "FAIL") +
          " trust=" + state.trust_score.toFixed(2) +
          " posture=" + state.posture +
          " caps=" + (state.capability_ok ? "ok" : "none"),
        ]),
      ]);
      list.appendChild(li);
    });
    return list;
  }

  function renderA2A(data) {
    if (!data) return el("p", { class: "v21__empty" }, ["no data"]);
    if (!data.relationships || !data.relationships.length) {
      return el("p", { class: "v21__empty" }, [data.note || "no relationships"]);
    }
    const list = el("ul", { class: "v21__list" });
    data.relationships.forEach((rel) => {
      const li = el("li", {}, [
        el("div", { class: "v21__evidence-row" }, [
          el("span", {}, [
            rel.initiator + " -> " + rel.responder,
          ]),
          el("span", { class: "v21__basis" }, [
            rel.task_id ? "task " + rel.task_id : "scoped",
          ]),
        ]),
        el("div", { class: "v21__basis" }, [
          JSON.stringify(rel.permissions || {}),
        ]),
      ]);
      list.appendChild(li);
    });
    return list;
  }

  function renderAttackGraph(data) {
    if (!data || !data.summary) return el("p", { class: "v21__empty" }, ["no graph"]);
    const summary = data.summary;
    const nodes = el("div", {}, [
      el("div", { class: "v21__evidence-row" }, [
        el("span", {}, ["agents"]),
        el("span", { class: "v21__basis" }, [String(summary.agents.length)]),
      ]),
      el("div", { class: "v21__evidence-row" }, [
        el("span", {}, ["nodes / edges"]),
        el("span", { class: "v21__basis" }, [
          summary.nodes + " / " + summary.edges,
        ]),
      ]),
      el("div", { class: "v21__evidence-row" }, [
        el("span", {}, ["sensitive resources"]),
        el("span", { class: "v21__basis" }, [
          String(summary.sensitive_resources.length),
        ]),
      ]),
    ]);
    const findings = el("div", {}, [
      el("p", { class: "v21__note" }, [
        "findings: " + (data.findings ? data.findings.length : 0) +
        " escalation path(s), " +
        (data.chokepoints ? data.chokepoints.length : 0) + " chokepoint(s). " +
        "Reachability is not exploitability.",
      ]),
    ]);
    return el("div", {}, [nodes, findings]);
  }

  function renderTwin(data) {
    if (!data) return el("p", { class: "v21__empty" }, ["run a simulation"]);
    if (data.error) return el("p", { class: "v21__empty" }, [data.error]);
    const rows = [];
    (data.reachability_deltas || []).forEach((delta) => {
      rows.push(
        el("div", { class: "v21__evidence-row" }, [
          el("span", {}, [delta.agent]),
          el("span", { class: "v21__basis" }, [
            "+" + delta.added_capabilities.length + " caps " +
            (delta.removed_capabilities.length ? "-" + delta.removed_capabilities.length + " caps " : "") +
            "risk delta " + delta.risk_delta(),
          ]),
        ])
      );
    });
    rows.push(
      el("p", { class: "v21__note" }, [
        "basis: " + (data.basis || "simulated") +
        " - simulated reach, never observed evidence.",
      ])
    );
    return el("div", {}, rows);
  }

  function renderEvidence(data) {
    if (!data) return el("p", { class: "v21__empty" }, ["no evidence"]);
    const verification = data.verification || {};
    const list = el("ul", { class: "v21__list" });
    (data.events || []).slice().reverse().forEach((event) => {
      const li = el("li", {}, [
        el("div", { class: "v21__evidence-row" }, [
          el("span", {}, [event.subject + " / " + event.event_type]),
          el("span", { class: "v21__basis" }, [
            "#" + event.seq + " " + event.kind,
          ]),
        ]),
        el("div", { class: "v21__basis" }, [event.event_id.slice(0, 16) + "..."]),
      ]);
      list.appendChild(li);
    });
    return el("div", {}, [
      el("p", { class: "v21__note" }, [
        "verification: " + (verification.status || "unknown") +
        " (" + (verification.events || 0) + " events)",
      ]),
      list,
    ]);
  }

  function renderImmune(data) {
    if (!data) return el("p", { class: "v21__empty" }, ["no state"]);
    const loop = el("p", { class: "v21__loop" }, [
      (data.loop || []).join(" -> "),
    ]);
    const detections = el("ul", { class: "v21__list" });
    (data.detections || []).slice().reverse().forEach((detection) => {
      const li = el("li", {}, [
        el("div", { class: "v21__evidence-row" }, [
          el("span", {}, [detection.rule_id]),
          el("span", { class: "v21__basis" }, [detection.severity]),
        ]),
        el("div", { class: "v21__basis" }, [detection.detail]),
      ]);
      detections.appendChild(li);
    });
    const actions = el("ul", { class: "v21__list" });
    (data.actions || []).slice().reverse().forEach((action) => {
      const li = el("li", {}, [
        el("div", { class: "v21__evidence-row" }, [
          el("span", {}, [action.action + " / " + action.outcome]),
          el("span", { class: "v21__basis" }, [action.rule_id]),
        ]),
        el("div", { class: "v21__basis" }, [action.detail]),
      ]);
      actions.appendChild(li);
    });
    return el("div", {}, [
      loop,
      el("p", { class: "v21__note" }, [data.authorization_model || ""]),
      el("p", { class: "v21__basis" }, [
        "detections: " + data.detections.length +
        " actions: " + data.actions.length,
      ]),
      actions,
    ]);
  }

  async function refresh() {
    const panel = document.querySelector("[data-bind='v21Panel']");
    if (!panel) return;

    const mesh = panel.querySelector("[data-bind='v21Mesh']");
    const a2a = panel.querySelector("[data-bind='v21A2A']");
    const attack = panel.querySelector("[data-bind='v21AttackGraph']");
    const evidence = panel.querySelector("[data-bind='v21Evidence']");
    const immune = panel.querySelector("[data-bind='v21Immune']");

    try {
      const [meshData, a2aData, attackData, evidenceData, immuneData] =
        await Promise.all([
          api("/api/v21/mesh"),
          api("/api/v21/a2a"),
          api("/api/v21/attack-graph"),
          api("/api/v21/evidence"),
          api("/api/v21/immune"),
        ]);
      bind(mesh, () => renderMesh(meshData));
      bind(a2a, () => renderA2A(a2aData));
      bind(attack, () => renderAttackGraph(attackData));
      bind(evidence, () => renderEvidence(evidenceData));
      bind(immune, () => renderImmune(immuneData));
    } catch (error) {
      bind(mesh, () => el("p", { class: "v21__empty" }, [String(error.message)]));
    }
  }

  function wire() {
    const panel = document.querySelector("[data-bind='v21Panel']");
    if (!panel) return;

    const refreshBtn = panel.querySelector("[data-bind='v21MeshRefresh']");
    if (refreshBtn) refreshBtn.addEventListener("click", refresh);

    const twinForm = panel.querySelector("[data-bind='v21TwinForm']");
    const twinResult = panel.querySelector("[data-bind='v21TwinResult']");
    if (twinForm) {
      twinForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const agent = panel
          .querySelector("[data-bind='v21TwinAgent']").value.trim();
        if (!agent) return;
        try {
          const data = await api("/api/v21/twin", { agent: agent });
          bind(twinResult, () => renderTwin(data));
        } catch (error) {
          bind(twinResult, () =>
            el("p", { class: "v21__empty" }, [String(error.message)])
          );
        }
      });
    }

    const immuneBtn = panel.querySelector("[data-bind='v21ImmuneCycle']");
    const immuneBox = panel.querySelector("[data-bind='v21Immune']");
    if (immuneBtn) {
      immuneBtn.addEventListener("click", async () => {
        try {
          const data = await api("/api/v21/immune/cycle", {});
          bind(immuneBox, () => renderImmune(data.state || data));
        } catch (error) {
          bind(immuneBox, () =>
            el("p", { class: "v21__empty" }, [String(error.message)])
          );
        }
      });
    }
  }

  window.addEventListener("DOMContentLoaded", () => {
    wire();
    refresh();
  });
})();
