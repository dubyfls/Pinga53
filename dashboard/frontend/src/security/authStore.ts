// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — client auth store. Token in sessionStorage (clears on browser close).
// authedFetch attaches the bearer token and auto-logs-out on 401.

const KEY = "pinga53.token";
const UKEY = "pinga53.user";

export const authStore = {
  token: () => sessionStorage.getItem(KEY),
  user: () => sessionStorage.getItem(UKEY),
  isAuthed: () => !!sessionStorage.getItem(KEY),

  async login(username: string, password: string, totp?: string) {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, totp: totp || undefined }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `login failed (${res.status})`);
    }
    const data = await res.json();
    sessionStorage.setItem(KEY, data.token);
    sessionStorage.setItem(UKEY, data.user);
    return data;
  },

  logout() {
    const t = this.token();
    if (t) fetch("/api/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${t}` } }).catch(() => {});
    sessionStorage.removeItem(KEY);
    sessionStorage.removeItem(UKEY);
  },
};

export async function authedFetch(path: string, init: RequestInit = {}) {
  const t = authStore.token();
  const res = await fetch(path, {
    ...init,
    headers: { ...(init.headers || {}), ...(t ? { Authorization: `Bearer ${t}` } : {}) },
  });
  if (res.status === 401) { authStore.logout(); window.location.reload(); }
  return res;
}
