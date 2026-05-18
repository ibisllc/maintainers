/**
 * Shared mutable state for the UI.
 *
 * The UI is structured as one StateStore + a set of view functions
 * that read it and produce DOM. Every view re-renders on state
 * change; there is no virtual DOM and no per-node diff — these
 * pages are small enough that wholesale re-renders are cheaper than
 * the cognitive load of a diff engine.
 *
 * **#31 — STATUS / PREVIEW ONLY (LOCKED Phase-2 v2 model).** No signing
 * happens here, so there is no onboarding draft / wizard state: only
 * home + the read-only project view.
 */

import type { AdapterClient, LoadedProject } from "./adapter.js";

export type Route =
  | { kind: "home" }
  | { kind: "project"; repoUrl: string; view: ProjectView };

export type ProjectView = "health" | "roster" | "activity";

export interface AppState {
  adapter: AdapterClient;
  rpId: string;
  rpName: string;
  now: Date;
  route: Route;
  loaded: LoadedProject | null;
  loading: boolean;
  error: string | null;
}

export type Listener = (s: AppState) => void;

export class StateStore {
  private listeners = new Set<Listener>();
  constructor(private state: AppState) {}

  get(): AppState {
    return this.state;
  }

  update(patch: Partial<AppState>): void {
    this.state = { ...this.state, ...patch };
    for (const l of this.listeners) l(this.state);
  }

  subscribe(l: Listener): () => void {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }
}
