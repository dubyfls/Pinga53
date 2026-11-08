// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — JSON API helper and first-login flow detection.
import { authStore } from "./authStore";

export class ApiError extends Error {
  status: number; code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message); this.status = status; this.code = code;
  }
}

/** Authenticated JSON call. Throws ApiError with the server's detail. 401 signs out. */
export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const t = authStore.token();
  const res = await fetch(path, {
    ...init,
    headers: {
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(init.headers || {}),
      ...(t ? { Authorization: `Bearer ${t}` } : {}),
    },
  });
  const body = await res.json().catch(() => ({}));
  // A 401 is either an expired/invalid session (sign out) or a wrong password /
  // MFA code on a form (show it). Only the session kind carries no form detail.
  if (res.status === 401 && /token|not authenticated|credential|unknown user/i.test(String(body.detail || "not authenticated"))) {
    authStore.logout(); window.location.reload();
  }
  if (!res.ok) throw new ApiError(res.status, body.detail || `request failed (${res.status})`, body.code);
  return body as T;
}

export type Account = {
  username: string; last_login: string | null; mfa_enrolled: boolean;
  disabled: boolean; recovery_codes_remaining: number; must_change_password: boolean;
};

/** What the signed-in account still owes. The server's forced-flow gate answers
 *  409 with a code on every route except the flow routes, so asking for the
 *  account summary is enough to learn the next step. */
export async function flowState(): Promise<{ step: "ok"; account: Account } | { step: "password" | "mfa" }> {
  try {
    const account = await api<Account>("/api/account");
    if (account.must_change_password) return { step: "password" };
    return { step: "ok", account };
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      if (e.code === "must_change_password") return { step: "password" };
      if (e.code === "must_enroll_mfa") return { step: "mfa" };
    }
    throw e;
  }
}
