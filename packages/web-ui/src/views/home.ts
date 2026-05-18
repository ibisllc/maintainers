/**
 * Home — a friendly landing page that looks up an existing project.
 *
 * **#31 — STATUS / PREVIEW ONLY (LOCKED Phase-2 v2 model).** The web UI
 * never signs, so there is no "set up a new project" wizard here:
 * onboarding (and every mandate-signing flow) happens on the
 * YubiKey-driven CLI. This page is a read-only lookup.
 */

import { el, mount } from "../dom.js";
import type { StateStore } from "../state.js";

export function renderHome(root: HTMLElement, store: StateStore): void {
  let lookup = "";
  mount(
    root,
    el(
      "div.home",
      null,
      el("h1", null, "maintainers"),
      el(
        "p.muted",
        null,
        "Cryptographic authority management for any git-versioned project. The YubiKey signs, the repo stores, every consumer verifies. This page is a read-only viewer.",
      ),
      el(
        "div.panel",
        null,
        el("h2", null, "Look up a project"),
        el("p.muted", null, "Already adopted? Enter the repo URL to see its current authority."),
        el("input", {
          type: "url",
          placeholder: "github.com/foo/bar",
          onInput: (e: Event) => {
            lookup = (e.target as HTMLInputElement).value.trim();
          },
        }),
        el(
          "div.row.end",
          null,
          el(
            "button.primary",
            {
              onClick: () => {
                if (!lookup) return;
                store.update({
                  route: { kind: "project", repoUrl: lookup, view: "health" },
                });
              },
            },
            "Look up",
          ),
        ),
      ),
    ),
  );
}
