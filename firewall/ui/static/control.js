/* Agent Firewall console -- control plane (write surface).
 *
 * Kept in its own file so the read-only console (console.js) stays
 * exactly what it was: a projection with no write path.
 *
 * Two rules this file follows without exception:
 *
 *  1. It never decides anything. Every verdict it shows came back from
 *     POST /api/control/check, which runs the real pipeline server-side.
 *  2. All server-provided strings reach the DOM through textContent, so
 *     an agent id or denial reason can never become markup.
 *
 * The token lives in memory only. It is deliberately not written to
 * localStorage or sessionStorage: it can mint authority, and persisting
 * it in browser storage would outlive the tab that earned it.
 */
(function () {
  "use strict";

  // ==================================================================
  // Helpers
  // ==================================================================

  function bind(name) {
    return document.querySelector('[data-bind="' + name + '"]');
  }

  function h(tag, attrs) {
    var node = document.createElement(tag);
    var key;

    if (attrs) {
      for (key in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, key)) continue;
        if (key === "text") {
          node.textContent = attrs[key];
        } else if (key === "class") {
          node.className = attrs[key];
        } else if (attrs[key] !== null && attrs[key] !== undefined) {
          node.setAttribute(key, attrs[key]);
        }
      }
    }

    for (var i = 2; i < arguments.length; i += 1) {
      var kid = arguments[i];
      if (kid === null || kid === undefined || kid === false) continue;
      node.appendChild(
        typeof kid === "string" ? document.createTextNode(kid) : kid
      );
    }

    return node;
  }

  function empty(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function clock(seconds) {
    if (typeof seconds !== "number") return "—";
    var d = new Date(seconds * 1000);
    return d.toLocaleTimeString([], { hour12: false }) +
      "." + String(d.getMilliseconds()).padStart(3, "0");
  }

  var state = {
    token: null,
    control: null,
    busy: false,
  };

  // ==================================================================
  // Transport
  // ==================================================================

  function request(path, body) {
    var init = {
      method: body === undefined ? "GET" : "POST",
      headers: { Authorization: "Bearer " + (state.token || "") },
    };

    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }

    return fetch(path, init).then(function (response) {
      return response.json().catch(function () {
        return {};
      }).then(function (payload) {
        if (!response.ok) {
          var message = payload && payload.error
            ? payload.error
            : "request failed (" + response.status + ")";
          var error = new Error(message);
          error.status = response.status;
          throw error;
        }
        return payload;
      });
    });
  }

  function status(message, kind) {
    var node = bind("controlStatus");
    if (!node) return;

    node.textContent = message || "";
    node.hidden = !message;
    node.setAttribute("data-kind", kind || "info");
  }

  // Every mutation funnels through here, so the UI can never drift from
  // the server's view of what actually happened.
  function mutate(path, body, describe) {
    if (state.busy) return Promise.resolve();
    state.busy = true;
    status("working…", "info");

    return request(path, body).then(function (payload) {
      state.control = payload.state;
      render();
      status(describe(payload.result), "ok");
      return payload;
    }).catch(function (error) {
      status("rejected: " + error.message, "error");
    }).then(function (payload) {
      state.busy = false;
      return payload;
    });
  }

  // ==================================================================
  // Rule rows
  //
  // A rule is a name plus a value. The value is parsed as JSON when it
  // parses (numbers, booleans, lists), otherwise kept as a string, so a
  // single input covers every constraint shape the server accepts.
  // ==================================================================

  function ruleRow(container, nameHint, valueHint) {
    var name = h("input", {
      class: "input input--sm",
      placeholder: nameHint,
      "data-rule": "name",
    });

    var value = h("input", {
      class: "input input--sm",
      placeholder: valueHint,
      "data-rule": "value",
    });

    var drop = h("button", {
      class: "btn btn--ghost btn--icon",
      type: "button",
      title: "remove rule",
      text: "×",
    });

    var row = h("div", { class: "rules__row" }, name, value, drop);

    drop.addEventListener("click", function () {
      container.removeChild(row);
    });

    container.appendChild(row);
    return row;
  }

  function readRules(container) {
    var out = {};

    if (!container) return out;

    var rows = container.querySelectorAll(".rules__row");

    for (var i = 0; i < rows.length; i += 1) {
      var name = rows[i].querySelector('[data-rule="name"]').value.trim();
      var raw = rows[i].querySelector('[data-rule="value"]').value.trim();

      if (!name) continue;

      var parsed = raw;

      if (raw === "") {
        parsed = true; // A bare rule name reads as "this flag is set".
      } else {
        try {
          parsed = JSON.parse(raw);
        } catch (err) {
          parsed = raw;
        }
      }

      out[name] = parsed;
    }

    return out;
  }

  function orNull(rules) {
    return Object.keys(rules).length ? rules : null;
  }

  // ==================================================================
  // Rendering
  // ==================================================================

  function shortFp(view) {
    return view.fingerprint_short || String(view.fingerprint || "").slice(0, 12);
  }

  function capabilityLabel(view) {
    return view.agent_id + " · " + view.capability + " · " + shortFp(view);
  }

  function renderTrustedIssuers(rules) {
    var host = bind("trustedIssuers");
    if (!host) return;

    empty(host);

    var issuers = (rules && rules.trusted_issuers) || [];

    if (!issuers.length) {
      host.appendChild(h("span", { class: "muted", text: "no issuers yet" }));
      return;
    }

    issuers.forEach(function (issuer) {
      host.appendChild(
        h("span", { class: "chip chip--trust", text: issuer })
      );
    });
  }

  function renderDepth(rules) {
    var input = bind("depthInput");
    if (!input || document.activeElement === input) return;

    var depth = rules ? rules.max_delegation_depth : null;
    input.value = typeof depth === "number" ? String(depth) : "";
  }

  function actionCell(view) {
    var wrap = h("div", { class: "rowactions" });

    var del = h("button", {
      class: "btn btn--sm", type: "button", text: "delegate",
    });

    var att = h("button", {
      class: "btn btn--sm", type: "button", text: "attenuate",
    });

    var rev = h("button", {
      class: "btn btn--sm btn--danger", type: "button", text: "revoke",
    });

    del.addEventListener("click", function () {
      openEditor(view, "delegate");
    });

    att.addEventListener("click", function () {
      openEditor(view, "attenuate");
    });

    rev.addEventListener("click", function () {
      if (!window.confirm(
        "Revoke " + capabilityLabel(view) +
        "?\n\nThis revokes it and everything delegated from it."
      )) return;

      mutate("/api/control/revoke", {
        fingerprint: view.fingerprint,
        reason: "revoked from console",
      }, function () {
        return "revoked " + shortFp(view);
      });
    });

    if (view.effectively_revoked) {
      del.disabled = true;
      att.disabled = true;
      rev.disabled = true;
    }

    wrap.appendChild(del);
    wrap.appendChild(att);
    wrap.appendChild(rev);
    return wrap;
  }

  // An inline editor row, so delegating never needs a modal or a prompt.
  function openEditor(view, kind) {
    var existing = document.querySelector(".editor");
    if (existing && existing.parentNode) {
      existing.parentNode.removeChild(existing);
    }

    var anchor = document.querySelector(
      '[data-row="' + view.fingerprint + '"]'
    );
    if (!anchor) return;

    var cell = h("td", { colspan: "7" });
    var row = h("tr", { class: "editor" }, cell);

    var delegatee = null;

    if (kind === "delegate") {
      delegatee = h("input", {
        class: "input input--sm",
        placeholder: "delegate to agent id",
      });
      cell.appendChild(
        h("label", { class: "field field--inline" },
          h("span", { class: "field__key", text: "delegatee" }),
          delegatee)
      );
    }

    var rules = h("div", { class: "rules__rows" });
    var add = h("button", {
      class: "btn btn--ghost btn--sm", type: "button", text: "+ add rule",
    });

    add.addEventListener("click", function () {
      ruleRow(rules, "amount_max", "100");
    });

    ruleRow(rules, "amount_max", "100");

    cell.appendChild(
      h("div", { class: "editor__rules" },
        h("span", {
          class: "field__key",
          text: kind === "delegate"
            ? "narrower rules for the child (optional)"
            : "narrower rules (required)",
        }),
        rules, add)
    );

    var apply = h("button", {
      class: "btn btn--primary btn--sm", type: "button", text: kind,
    });

    var cancel = h("button", {
      class: "btn btn--ghost btn--sm", type: "button", text: "cancel",
    });

    cancel.addEventListener("click", function () {
      if (row.parentNode) row.parentNode.removeChild(row);
    });

    apply.addEventListener("click", function () {
      var body = {
        fingerprint: view.fingerprint,
        constraints: orNull(readRules(rules)),
      };

      if (kind === "delegate") {
        body.delegatee = delegatee.value.trim();
      }

      mutate("/api/control/" + kind, body, function (result) {
        return kind + "d " + capabilityLabel(result);
      });
    });

    cell.appendChild(h("div", { class: "editor__actions" }, apply, cancel));

    cell.appendChild(
      h("p", {
        class: "editor__note",
        text: "Attenuation is enforced by the pipeline; a widening rule " +
          "will be rejected there, not here.",
      })
    );

    anchor.parentNode.insertBefore(row, anchor.nextSibling);
    if (delegatee) delegatee.focus();
  }

  function renderAgents(agents) {
    var table = bind("agentTable");
    var count = bind("agentCount");

    if (!table) return;

    empty(table);

    var total = 0;
    agents.forEach(function (entry) {
      total += entry.capabilities.length;
    });

    if (count) count.textContent = String(agents.length);

    table.appendChild(
      h("thead", null,
        h("tr", null,
          h("th", { text: "agent" }),
          h("th", { text: "capability" }),
          h("th", { text: "fingerprint" }),
          h("th", { text: "rules" }),
          h("th", { text: "tool" }),
          h("th", { text: "state" }),
          h("th", { text: "" })))
    );

    var body = h("tbody");

    if (!total) {
      body.appendChild(
        h("tr", null,
          h("td", {
            colspan: "7",
            class: "muted",
            text: "No agents connected yet. Use “Connect an agent”.",
          }))
      );
    }

    agents.forEach(function (entry) {
      entry.capabilities.forEach(function (view) {
        var constraints = view.constraints || {};
        var names = Object.keys(constraints);

        var rules = names.length
          ? names.map(function (name) {
            return name + "=" + JSON.stringify(constraints[name]);
          }).join("  ")
          : "—";

        var revoked = view.effectively_revoked;

        var row = h("tr", { "data-row": view.fingerprint },
          h("td", null, h("strong", { text: view.agent_id })),
          h("td", { class: "mono", text: view.capability }),
          h("td", { class: "mono dim", text: shortFp(view) }),
          h("td", { class: "mono small", text: rules }),
          h("td", { class: "mono dim", text: view.tool || "—" }),
          h("td", null,
            h("span", {
              class: "pill " + (revoked ? "pill--deny" : "pill--allow"),
              text: revoked
                ? (view.revoked ? "revoked" : "revoked (ancestor)")
                : "live",
            })),
          h("td", null, actionCell(view)));

        body.appendChild(row);
      });
    });

    table.appendChild(body);
  }

  function renderTargets(agents) {
    var select = bind("checkTarget");
    if (!select) return;

    var previous = select.value;
    empty(select);

    var any = false;

    agents.forEach(function (entry) {
      entry.capabilities.forEach(function (view) {
        any = true;
        select.appendChild(
          h("option", {
            value: view.fingerprint,
            text: capabilityLabel(view) +
              (view.effectively_revoked ? " (revoked)" : ""),
          })
        );
      });
    });

    if (!any) {
      select.appendChild(
        h("option", { value: "", text: "no capabilities yet" })
      );
    }

    if (previous) select.value = previous;
  }

  function renderAudit(entries) {
    var table = bind("auditTable");
    if (!table) return;

    empty(table);

    table.appendChild(
      h("thead", null,
        h("tr", null,
          h("th", { text: "#" }),
          h("th", { text: "time" }),
          h("th", { text: "action" }),
          h("th", { text: "outcome" }),
          h("th", { text: "target" }),
          h("th", { text: "detail" })))
    );

    var body = h("tbody");

    if (!entries.length) {
      body.appendChild(
        h("tr", null,
          h("td", { colspan: "6", class: "muted", text: "No actions yet." }))
      );
    }

    entries.forEach(function (entry) {
      var detail = entry.ok
        ? JSON.stringify(entry.detail || {})
        : String(entry.error || "");

      body.appendChild(
        h("tr", null,
          h("td", { class: "mono dim", text: String(entry.seq) }),
          h("td", { class: "mono dim", text: clock(entry.timestamp) }),
          h("td", { class: "mono", text: entry.action }),
          h("td", null,
            h("span", {
              class: "pill " + (entry.ok ? "pill--allow" : "pill--deny"),
              text: entry.ok ? "applied" : "rejected",
            })),
          h("td", { class: "mono", text: entry.target || "—" }),
          h("td", { class: "mono small dim", text: detail }))
      );
    });

    table.appendChild(body);
  }

  function render() {
    var control = state.control;
    if (!control) return;

    renderDepth(control.rules);
    renderTrustedIssuers(control.rules);
    renderAgents(control.agents || []);
    renderTargets(control.agents || []);
    renderAudit(control.audit || []);
  }

  // ==================================================================
  // Unlocking
  // ==================================================================

  function unlock() {
    var input = bind("tokenInput");
    if (!input) return;

    var token = input.value.trim();

    if (!token) {
      status("paste the control token printed at startup", "error");
      return;
    }

    state.token = token;

    request("/api/control/state").then(function (payload) {
      state.control = payload;
      input.value = "";

      var auth = bind("controlAuth");
      var body = bind("controlBody");
      var lock = bind("controlLock");

      if (auth) auth.hidden = true;
      if (body) body.hidden = false;
      if (lock) {
        lock.textContent = "unlocked";
        lock.setAttribute("data-state", "open");
      }

      render();
      status("control plane unlocked. Actions from here are audited.", "ok");
    }).catch(function (error) {
      state.token = null;
      status(
        error.status === 401
          ? "token rejected"
          : "could not reach the control plane: " + error.message,
        "error"
      );
    });
  }

  // ==================================================================
  // Forms
  // ==================================================================

  function fieldValue(form, name) {
    var node = form.elements[name];
    if (!node) return "";
    return node.value.trim();
  }

  function wireConnect() {
    var form = bind("connectForm");
    var rules = bind("connectRules");
    var add = bind("addConnectRule");

    if (!form) return;

    if (add && rules) {
      add.addEventListener("click", function () {
        ruleRow(rules, "amount_max", "1000");
      });
      ruleRow(rules, "amount_max", "1000");
    }

    form.addEventListener("submit", function (event) {
      event.preventDefault();

      var ttl = fieldValue(form, "expires_in");

      var body = {
        agent: fieldValue(form, "agent"),
        capability: fieldValue(form, "capability"),
        issuer: fieldValue(form, "issuer") || null,
        tool: fieldValue(form, "tool") || null,
        constraints: orNull(readRules(rules)),
      };

      if (ttl) body.expires_in = Number(ttl);

      mutate("/api/control/connect", body, function (result) {
        return "connected " + capabilityLabel(result);
      });
    });
  }

  function wireRules() {
    var depth = bind("depthForm");
    var trust = bind("trustForm");
    var untrust = bind("untrustBtn");

    if (depth) {
      depth.addEventListener("submit", function (event) {
        event.preventDefault();
        var raw = fieldValue(depth, "max_delegation_depth");

        mutate("/api/control/depth", {
          max_delegation_depth: raw === "" ? null : Number(raw),
        }, function (result) {
          var value = result.max_delegation_depth;
          return "depth policy: " +
            (value === null ? "unbounded" : "max " + value);
        });
      });
    }

    function setTrust(trusted) {
      var issuer = fieldValue(trust, "issuer");

      mutate("/api/control/trust", {
        issuer: issuer,
        trusted: trusted,
      }, function (result) {
        return result.issuer +
          (result.trusted ? " is trusted" : " is no longer trusted");
      });
    }

    if (trust) {
      trust.addEventListener("submit", function (event) {
        event.preventDefault();
        setTrust(true);
      });
    }

    if (untrust) {
      untrust.addEventListener("click", function () {
        setTrust(false);
      });
    }
  }

  function wireCheck() {
    var form = bind("checkForm");
    var rules = bind("checkRules");
    var add = bind("addCheckRule");

    if (!form) return;

    if (add && rules) {
      add.addEventListener("click", function () {
        ruleRow(rules, "amount", "50");
      });
      ruleRow(rules, "amount", "50");
    }

    form.addEventListener("submit", function (event) {
      event.preventDefault();

      var fingerprint = fieldValue(form, "fingerprint");

      if (!fingerprint) {
        status("connect an agent first", "error");
        return;
      }

      mutate("/api/control/check", {
        fingerprint: fingerprint,
        action: fieldValue(form, "action"),
        request: readRules(rules),
      }, function (result) {
        var decision = result.decision;
        // Reported, not computed. The verdict and its reason are the
        // server's words verbatim.
        return (decision.allowed ? "ALLOW" : "DENY") + " — " + decision.reason;
      }).then(function (payload) {
        if (payload && payload.result) {
          paint(payload.result);
        }
      });
    });
  }

  // The console's own renderers are top-level functions in console.js.
  // Reusing them means a control-plane request is visualized by exactly
  // the same code path as a demo scenario -- one pipeline diagram, one
  // decision panel, no second opinion.
  function paint(result) {
    if (typeof renderPipeline !== "function") return;

    result.scenario = "control-plane request (authored in this console)";

    renderPipeline(result.phases, { animate: true });
    renderAttribution(result);
    renderDecision(result);
    renderAuthority(result.authority);
    renderTrace(result);
  }

  // ==================================================================
  // Boot
  // ==================================================================

  function boot() {
    fetch("/api/system").then(function (r) {
      return r.json();
    }).then(function (system) {
      if (!system.control_enabled) return;

      var panel = bind("controlPanel");
      var note = bind("disclosureWrite");

      if (panel) panel.hidden = false;
      if (note) note.hidden = false;

      var button = bind("unlock");
      var input = bind("tokenInput");

      if (button) button.addEventListener("click", unlock);
      if (input) {
        input.addEventListener("keydown", function (event) {
          if (event.key === "Enter") {
            event.preventDefault();
            unlock();
          }
        });
      }

      wireConnect();
      wireRules();
      wireCheck();
    }).catch(function () {
      /* Read-only console; nothing to enable. */
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
