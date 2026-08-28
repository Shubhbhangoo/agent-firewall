/* ==========================================================================
   Agent Firewall v2.0 -- Control Plane panel (identity / passport /
   provenance).

   Renders GET /api/v20/identities, GET /api/v20/provenance, and
   POST /api/v20/passport. Mutations (identity create/revoke/rotate,
   provenance register/trust/suspect/revoke) go through
   /api/control/* routes behind the bearer-token gate.

   This file renders. It never computes security state client-side.
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
  // Identities
  // ----------------------------------------------------------------

  function renderIdentities(view) {
    const slot = bind("v20Identities");
    const identities = (view && view.identities) || [];

    if (!identities.length) {
      fill(slot, h("p", { class: "empty", text: "No identities. Create one from the control plane." }));
      return;
    }

    fill(
      slot,
      identities.map((identity) =>
        h(
          "div",
          { class: "ident", "data-status": identity.status },
          h("div", { class: "ident__head" },
            h("span", { class: "ident__name", text: identity.agent_id }),
            h("span", { class: `pill pill--${identity.status}`, text: identity.status }),
          ),
          h("p", { class: "ident__meta",
            text: `v${identity.identity_version} owner: ${identity.owner || "-"} ` +
              `issuer: ${identity.issuer}` }),
          h("p", { class: "ident__meta ident__meta--mono",
            text: "key: " + (identity.key_fingerprint || "-").slice(0, 16) + "..." }),
          identity.parent_agent
            ? h("p", { class: "ident__meta", text: `parent: ${identity.parent_agent}` })
            : null,
        ),
      ),
    );
  }

  // ----------------------------------------------------------------
  // Passport
  // ----------------------------------------------------------------

  async function showPassport(agent) {
    const slot = bind("v20Passport");
    fill(slot, h("p", { class: "empty", text: "Building passport..." }));

    try {
      const result = await api("/api/v20/passport", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent }),
      });

      const passport = result.passport || {};
      const verification = result.verification || {};

      fill(
        slot,
        h("div", { class: "passport" },
          h("div", { class: "passport__head" },
            h("span", { class: "ident__name", text: passport.identity && passport.identity.agent_id }),
            h("span", { class: `pill pill--${verification.status || "unknown"}`, text: `verification: ${verification.status}` }),
          ),
          h("p", { class: "passport__line",
            text: `posture: ${(passport.posture && passport.posture.posture) || "unknown"} ` +
              `| tasks: ${(passport.tasks || []).length} ` +
              `| capabilities: ${(passport.capabilities || []).join(", ") || "none"}` }),
          h("p", { class: "passport__line",
            text: `signature: ${passport.signature ? "present" : "MISSING"}` }),
          (verification.findings || []).map((finding) =>
            h("p", { class: "passport__line passport__line--warn", text: finding }),
          ),
        ),
      );
    } catch (error) {
      fill(slot, h("p", { class: "empty", text: `Passport failed: ${error.message}` }));
    }
  }

  // ----------------------------------------------------------------
  // Provenance
  // ----------------------------------------------------------------

  function renderProvenance(view) {
    const slot = bind("v20Provenance");
    const components = (view && view.components) || [];

    if (!components.length) {
      fill(slot, h("p", { class: "empty", text: "No components registered." }));
      return;
    }

    fill(
      slot,
      components.map((component) =>
        h(
          "div",
          { class: "prov", "data-status": component.status },
          h("div", { class: "prov__head" },
            h("span", { class: "prov__name", text: `${component.name} ${component.version}` }),
            h("span", { class: `pill pill--${component.status}`, text: component.status }),
          ),
          h("p", { class: "prov__meta",
            text: `${component.kind} | ${component.component_id}` }),
          component.integrity
            ? h("p", { class: "prov__meta prov__meta--mono", text: `sha256: ${component.integrity.slice(0, 16)}...` })
            : h("p", { class: "prov__meta prov__meta--warn", text: "no integrity digest recorded" }),
        ),
      ),
    );
  }

  // ----------------------------------------------------------------
  // Boot
  // ----------------------------------------------------------------

  async function loadV20() {
    try {
      const [identities, provenance] = await Promise.all([
        api("/api/v20/identities"),
        api("/api/v20/provenance"),
      ]);

      renderIdentities(identities);
      renderProvenance(provenance);

      const button = bind("v20PassportBtn");
      if (button) {
        button.addEventListener("click", () => {
          const agent = bind("v20PassportAgent").value.trim();
          if (agent) showPassport(agent);
        });
      }
    } catch (error) {
      fill(bind("v20Panel"), h("p", { class: "empty", text: `v2.0 unavailable: ${error.message}` }));
    }
  }

  document.addEventListener("DOMContentLoaded", loadV20);
})();
