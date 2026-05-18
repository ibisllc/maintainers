/**
 * Project view — once a `.maintainers/` folder has been loaded for a
 * given repo, this renders three tabs:
 *
 *   - health    : per-track status, time-to-expiry, current authority,
 *                 named successors, recent activity
 *   - roster    : named keys + emails + role + avatar placeholder
 *   - activity  : last N envelopes by kind, newest first
 *
 * **#31 — STATUS / PREVIEW ONLY (LOCKED Phase-2 v2 model).** This view
 * never signs. It verifies each track's mandate log FORWARD from the
 * first on-repo mandate (the read-only-preview anchor — the web UI has
 * no baked pin; a real consumer bakes `mandatePinHash` of a chosen
 * mandate, see the v2 security boundary) via `verifyMandateChainFromPin`
 * + `currentAuthorityV2`. There is no policy.json / rootPolicy /
 * TrackPolicy: the succession rule is inline in each mandate.
 */

import {
  currentAuthorityV2,
  mandatePinHash,
  verifyMandateChainFromPin,
  type MandateV2,
  type VerifiedChainV2,
} from "@maintainers/protocol";
import { daysFromNow, el, mount, relativeTime, shortHex } from "../dom.js";
import { lookupHolder, type ParsedFolder, type ParsedTrack } from "../parse-folder.js";
import type { ProjectView, StateStore } from "../state.js";

export function renderProject(view: ProjectView, root: HTMLElement, store: StateStore): void {
  const state = store.get();
  if (state.loading) {
    mount(root, el("div.panel", null, el("p", null, "Loading…")));
    return;
  }
  if (state.error) {
    mount(root, el("div.alert.err", null, state.error));
    return;
  }
  if (!state.loaded) {
    mount(root, el("div.panel", null, el("p", null, "No project loaded.")));
    return;
  }
  if (!state.loaded.exists) {
    mount(
      root,
      el(
        "div.panel",
        null,
        el("h2", null, "No `.maintainers/` folder yet"),
        el(
          "p.muted",
          null,
          "This repo doesn't have a maintainers folder yet. Set one up with the maintainers CLI.",
        ),
      ),
    );
    return;
  }

  const folder = state.loaded.folder;
  const repoUrl = state.loaded.ref.canonical;
  let body: HTMLElement;
  switch (view) {
    case "health":
      body = renderHealth(folder, store.get().now);
      break;
    case "roster":
      body = renderRoster(folder);
      break;
    case "activity":
      body = renderActivity(folder, state.now);
      break;
  }

  mount(
    root,
    el(
      "div.project",
      null,
      el("h1", null, projectName(folder) ?? repoUrl),
      el("p.muted", null, repoUrl),
      tabs(view, store),
      body,
    ),
  );
}

/**
 * v2: project metadata lives inline on the from-scratch (root) mandate
 * of any track (not in a policy.json). Surface the first one we see.
 */
function projectName(folder: ParsedFolder): string | null {
  for (const t of folder.tracks) {
    for (const m of t.mandates) {
      if (m.project?.name) return m.project.name;
    }
  }
  return null;
}

/** Forward-verify a track anchored at its first on-repo mandate. */
function verifyTrackChain(track: ParsedTrack): VerifiedChainV2 | null {
  if (track.mandates.length === 0) return null;
  return verifyMandateChainFromPin(mandatePinHash(track.mandates[0]!), track.mandates);
}

function tabs(active: ProjectView, store: StateStore): HTMLElement {
  const repoUrl = store.get().loaded?.ref.canonical ?? "";
  const set = (v: ProjectView) => () =>
    store.update({ route: { kind: "project", repoUrl, view: v } });
  return el(
    "nav.tabs",
    null,
    el(`a${active === "health" ? ".active" : ""}`, { onClick: set("health") }, "Health"),
    el(`a${active === "roster" ? ".active" : ""}`, { onClick: set("roster") }, "Roster"),
    el(`a${active === "activity" ? ".active" : ""}`, { onClick: set("activity") }, "Activity"),
  );
}

// ---- Health ----

function renderHealth(folder: ParsedFolder, now: Date): HTMLElement {
  return el(
    "div.health",
    null,
    ...folder.tracks.map((t) => renderTrackHealth(t, folder, now)),
    folder.tracks.length === 0
      ? el("div.alert.warn", null, "No tracks declared in this project.")
      : null,
  );
}

function renderTrackHealth(
  track: ParsedTrack,
  folder: ParsedFolder,
  now: Date,
): HTMLElement {
  const chain = verifyTrackChain(track);
  if (!chain) {
    return el(
      "div.panel",
      null,
      el("h2", null, `Track: ${track.name}`),
      el("div.alert.warn", null, "No mandates on this track yet."),
    );
  }
  const auth = currentAuthorityV2(chain, now);
  // v2 has no holder-in-window vs after-expiry split — the last valid
  // mandate is simply the most recent succession; if its window has
  // elapsed, its named `successors` are who may continue (informational
  // for this read-only view).
  const last: MandateV2 | undefined = chain.validMandates[chain.validMandates.length - 1];
  const expired = !auth ? last ?? null : null;
  const head = el(
    "div.row",
    null,
    el("h2.grow", null, `Track: ${track.name}`),
    auth ? el("span.badge.ok", null, "Active") : el("span.badge.warn", null, "No active mandate"),
  );
  let mandateSection: HTMLElement;
  if (auth) {
    const holder = lookupHolder(folder, auth.holder);
    const daysLeft = daysFromNow(auth.mandate.expiresAt, now);
    const expiringSoon = daysLeft <= 14;
    mandateSection = el(
      "div",
      null,
      el(
        "p",
        null,
        "Held by ",
        holder
          ? el("strong", null, `${holder.displayName} <${holder.email}>`)
          : el("span.pubkey", null, shortHex(auth.holder, 8, 6)),
      ),
      el(
        "p",
        null,
        `Expires ${relativeTime(auth.mandate.expiresAt, now)}`,
        " ",
        expiringSoon ? el("span.badge.warn", null, "Renew soon") : el("span.badge.ok", null, "OK"),
      ),
      el(
        "p.muted",
        null,
        `Issued ${relativeTime(auth.mandate.issuedAt, now)}; mandate id ${auth.mandate.mandateId.slice(0, 8)}…`,
      ),
      auth.successors.length > 0
        ? el(
            "div",
            null,
            el("h3", null, "Successors"),
            ...auth.successors.map((s) => renderSuccessorChip(s, folder)),
          )
        : el("p.muted", null, "No successors named. Add some on the next renewal."),
    );
  } else if (expired) {
    const expiredHolder = lookupHolder(folder, expired.holder);
    mandateSection = el(
      "div",
      null,
      el(
        "div.alert.warn",
        null,
        `Mandate expired ${relativeTime(expired.expiresAt, now)}. Any named successor may continue the track.`,
      ),
      el(
        "p",
        null,
        "Previous holder: ",
        expiredHolder
          ? el("strong", null, `${expiredHolder.displayName} <${expiredHolder.email}>`)
          : el("span.pubkey", null, shortHex(expired.holder, 8, 6)),
      ),
      expired.successors.length > 0
        ? el(
            "div",
            null,
            el("h3", null, "Named successors"),
            ...expired.successors.map((s) => renderSuccessorChip(s, folder)),
          )
        : el("div.alert.err", null, "No successors were named on the expired mandate; nobody can continue without manual intervention."),
    );
  } else {
    mandateSection = el(
      "p.muted",
      null,
      chain.rootError
        ? `Chain could not be anchored (${chain.rootError}).`
        : "No valid mandates yet.",
    );
  }
  const rejectionsSection =
    chain.rejections.length > 0
      ? el(
          "details",
          null,
          el("summary", null, `${chain.rejections.length} rejected mandate(s)`),
          ...chain.rejections.map((r) =>
            el(
              "p.hint",
              null,
              `${r.mandate.mandateId.slice(0, 8)}…: ${r.reason}${r.detail ? ` (${r.detail})` : ""}`,
            ),
          ),
        )
      : null;
  return el("div.panel", null, head, mandateSection, rejectionsSection);
}

function renderSuccessorChip(pubKey: string, folder: ParsedFolder): HTMLElement {
  const h = lookupHolder(folder, pubKey);
  return el(
    "p",
    null,
    h
      ? el("span", null, `${h.displayName} `)
      : null,
    el("span.pubkey", null, shortHex(pubKey, 8, 6)),
    h ? el("span.muted", null, ` <${h.email}>`) : null,
  );
}

// ---- Roster ----

function renderRoster(folder: ParsedFolder): HTMLElement {
  if (folder.keys.length === 0) {
    return el("div.panel", null, el("p", null, "No keys named yet."));
  }
  return el(
    "div.panel",
    null,
    el("h2", null, "Keys"),
    el(
      "table",
      null,
      el(
        "thead",
        null,
        el(
          "tr",
          null,
          el("th", null, "Person"),
          el("th", null, "Email"),
          el("th", null, "Role"),
          el("th", null, "Pubkey"),
        ),
      ),
      el(
        "tbody",
        null,
        ...folder.keys.flatMap((k) => {
          if (k.redirect) {
            return [
              el(
                "tr",
                null,
                el("td", null, el("em", null, "(redirected)")),
                el("td", null, k.email, " → ", k.redirect.renamedTo),
                el("td", null, ""),
                el("td", null, el("span.pubkey", null, shortHex(k.redirect.pubkey))),
              ),
            ];
          }
          if (!k.keyfile) return [];
          return [
            el(
              "tr",
              null,
              el("td", null, el("span.avatar", null, initials(k.keyfile.displayName)), k.keyfile.displayName),
              el("td", null, k.keyfile.currentEmail),
              el("td", null, k.keyfile.metadata.role ?? ""),
              el("td", null, el("span.pubkey", null, shortHex(k.keyfile.pubkey))),
            ),
          ];
        }),
      ),
    ),
  );
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  if (parts.length === 0) return "?";
  const first = parts[0]![0] ?? "?";
  const last = parts.length > 1 ? parts[parts.length - 1]![0] ?? "" : "";
  return (first + last).toUpperCase();
}

// ---- Activity ----

function renderActivity(folder: ParsedFolder, now: Date): HTMLElement {
  // Collate all envelopes by their canonical time field. For mandates
  // and endorsements that's issuedAt; for KeyFile we don't have a
  // signed timestamp — we use the redirect or skip.
  type Row = { when: number; kind: string; summary: string };
  const rows: Row[] = [];
  for (const t of folder.tracks) {
    for (const m of t.mandates) {
      rows.push({
        when: Date.parse(m.issuedAt),
        kind: `Mandate (${t.name})`,
        summary: `${m.signedBy === m.holder ? "self-issued" : "succession"} by ${shortHex(m.holder)} until ${m.expiresAt}`,
      });
    }
  }
  for (const e of folder.endorsements) {
    rows.push({
      when: Date.parse(e.issuedAt),
      kind: "Release",
      summary: `${e.semverTag} at commit ${e.commitHash.slice(0, 8)}`,
    });
  }
  for (const k of folder.keys) {
    if (k.redirect) {
      rows.push({
        when: Date.parse(k.redirect.renamedAt),
        kind: "KeyRedirect",
        summary: `${k.redirect.fromEmail} → ${k.redirect.renamedTo}`,
      });
    }
  }
  rows.sort((a, b) => b.when - a.when);
  if (rows.length === 0) {
    return el("div.panel", null, el("p", null, "No envelopes yet."));
  }
  return el(
    "div.panel",
    null,
    el("h2", null, "Recent activity"),
    el(
      "table",
      null,
      el(
        "thead",
        null,
        el(
          "tr",
          null,
          el("th", null, "When"),
          el("th", null, "Kind"),
          el("th", null, "Detail"),
        ),
      ),
      el(
        "tbody",
        null,
        ...rows.slice(0, 50).map((r) =>
          el(
            "tr",
            null,
            el("td", null, relativeTime(new Date(r.when).toISOString(), now)),
            el("td", null, r.kind),
            el("td", null, r.summary),
          ),
        ),
      ),
    ),
  );
}

/** Exported for tests: forward-verify a track's v2 mandate log. */
export function _verifyChainForTest(mandates: MandateV2[]): VerifiedChainV2 {
  return verifyMandateChainFromPin(
    mandates.length > 0 ? mandatePinHash(mandates[0]!) : "",
    mandates,
  );
}
