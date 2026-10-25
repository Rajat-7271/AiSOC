'use client';

import { FormEvent, useEffect, useState } from 'react';

type InvitationState = 'checking' | 'valid' | 'invalid' | 'redeemed';

const INVALID_MESSAGE = 'This invitation is invalid, expired, or already used. Request a new invitation from your administrator.';

export function InviteAcceptanceForm({
  token,
  tenantSlug,
}: {
  token: string;
  tenantSlug: string;
}) {
  const [state, setState] = useState<InvitationState>('checking');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    void fetch('/api/v1/auth/invitations/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, tenant: tenantSlug }),
      cache: 'no-store',
    })
      .then(async (response) => {
        if (!response.ok) throw new Error('validation failed');
        const result = (await response.json()) as { valid?: boolean };
        if (active) setState(result.valid ? 'valid' : 'invalid');
      })
      .catch(() => {
        if (active) {
          setState('invalid');
          setError('We could not validate this invitation. Check the link or request a new one.');
        }
      });
    return () => {
      active = false;
    };
  }, [tenantSlug, token]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    if (password !== confirmation) {
      setError('Passwords do not match.');
      return;
    }
    if (password.length < 12 || new TextEncoder().encode(password).length > 72) {
      setError('Use at least 12 characters and no more than 72 UTF-8 bytes.');
      return;
    }

    setBusy(true);
    try {
      const response = await fetch('/api/v1/auth/invitations/redeem', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, tenant: tenantSlug, password }),
        cache: 'no-store',
      });
      if (!response.ok) {
        setError(response.status === 429 ? 'Too many attempts. Wait a while and try again.' : INVALID_MESSAGE);
        if (response.status === 400) setState('invalid');
        return;
      }
      setPassword('');
      setConfirmation('');
      setState('redeemed');
    } catch {
      setError('We could not complete account setup. Check your connection and try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-surface-base px-4 py-12 text-white">
      <section className="w-full max-w-md rounded-2xl border border-white/10 bg-white/[0.03] p-8 shadow-xl">
        <h1 className="text-2xl font-semibold">Set up your administrator account</h1>
        {state === 'checking' && <p className="mt-4 text-sm text-gray-300">Checking invitation…</p>}
        {state === 'invalid' && (
          <p role="alert" className="mt-4 text-sm text-red-300">
            {error || INVALID_MESSAGE}
          </p>
        )}
        {state === 'redeemed' && (
          <div className="mt-4 space-y-4" role="status">
            <p className="text-sm text-emerald-300">Your administrator account is ready. Sign in with the password you just set.</p>
            <a className="inline-flex rounded-md bg-brand-500 px-4 py-2 text-sm font-medium text-white" href="/login">
              Go to sign in
            </a>
          </div>
        )}
        {state === 'valid' && (
          <form className="mt-6 space-y-4" onSubmit={submit}>
            <label className="block text-sm">
              Password
              <input
                autoComplete="new-password"
                className="mt-1 w-full rounded-md border border-white/15 bg-black/20 px-3 py-2 text-white"
                type="password"
                minLength={12}
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
            <label className="block text-sm">
              Confirm password
              <input
                autoComplete="new-password"
                className="mt-1 w-full rounded-md border border-white/15 bg-black/20 px-3 py-2 text-white"
                type="password"
                minLength={12}
                required
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
              />
            </label>
            {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
            <p className="text-xs text-gray-400">Use at least 12 characters. Passwords are limited to 72 UTF-8 bytes.</p>
            <button
              className="w-full rounded-md bg-brand-500 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
              disabled={busy}
              type="submit"
            >
              {busy ? 'Setting password…' : 'Set password'}
            </button>
          </form>
        )}
      </section>
    </main>
  );
}
