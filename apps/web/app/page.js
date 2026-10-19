"use client";

import { useEffect, useState } from "react";

export default function HomePage() {
  const [apiBaseUrl, setApiBaseUrl] = useState("");
  const [user, setUser] = useState(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function loadSession(apiUrl) {
    try {
      const response = await fetch(`${apiUrl}/auth/me`, { credentials: "include" });
      setUser(response.ok ? await response.json() : null);
    } catch {
      setUser(null);
      setMessage("Authentication service is unavailable.");
    }
  }

  useEffect(() => {
    fetch("/api/runtime-config")
      .then(async (response) => {
        if (!response.ok) throw new Error("Runtime configuration unavailable");
        const configuration = await response.json();
        setApiBaseUrl(configuration.apiBaseUrl);
        return loadSession(configuration.apiBaseUrl);
      })
      .catch(() => setMessage("Authentication service is unavailable."));
  }, []);

  async function signIn(event) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const response = await fetch(`${apiBaseUrl}/auth/login`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!response.ok) { setMessage("Email or password is incorrect."); return; }
      setPassword("");
      await loadSession(apiBaseUrl);
    } catch {
      setMessage("Authentication service is unavailable.");
    } finally { setBusy(false); }
  }

  async function signOut() {
    setBusy(true);
    setMessage("");
    try {
      const response = await fetch(`${apiBaseUrl}/auth/logout`, { method: "POST", credentials: "include" });
      if (!response.ok) setMessage("Could not end the session. Try again.");
      else setUser(null);
    } catch {
      setMessage("Authentication service is unavailable.");
    } finally { setBusy(false); }
  }

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="page-title">
        <h1 id="page-title">FinSight AI</h1>
        {user ? <>
          <p role="status">Signed in as {user.display_name} ({user.email})</p>
          <button type="button" onClick={signOut} disabled={busy || !apiBaseUrl}>Sign out</button>
        </> : <form onSubmit={signIn}>
          <h2>Sign in</h2>
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" autoComplete="username" required
            value={email} onChange={(event) => setEmail(event.target.value)} />
          <label htmlFor="password">Password</label>
          <input id="password" name="password" type="password" autoComplete="current-password"
            required value={password} onChange={(event) => setPassword(event.target.value)} />
          <button type="submit" disabled={busy || !apiBaseUrl}>{busy ? "Signing in…" : "Sign in"}</button>
        </form>}
        <p className="message" role="status" aria-live="polite">{message}</p>
        <p className="onboarding-note">Accounts are provisioned by an administrator. Public registration is unavailable.</p>
      </section>
      <style jsx>{`
        .auth-shell { min-height: 100vh; display: grid; place-items: center; padding: 1.5rem; background: #f4f6f8; color: #16202a; }
        .auth-card { width: min(100%, 26rem); padding: 2rem; border-radius: 0.75rem; background: white; box-shadow: 0 0.5rem 2rem #14253618; }
        h1 { margin-top: 0; } form { display: grid; gap: 0.7rem; } h2 { margin-bottom: 0.25rem; }
        input, button { min-height: 2.75rem; padding: 0.6rem 0.75rem; border: 1px solid #8b98a5; border-radius: 0.35rem; font: inherit; }
        button { margin-top: 0.6rem; background: #123c60; color: white; cursor: pointer; }
        button:disabled { opacity: 0.65; cursor: wait; } :focus-visible { outline: 3px solid #1673ba; outline-offset: 2px; }
        .message { min-height: 1.5rem; color: #9d1c1c; } .onboarding-note { font-size: 0.9rem; color: #4c5965; }
      `}</style>
    </main>
  );
}
