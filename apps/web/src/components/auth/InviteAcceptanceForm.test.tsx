import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { InviteAcceptanceForm } from './InviteAcceptanceForm';

const token = 'a'.repeat(43);
const jsonResponse = (body: unknown) => ({
  ok: true,
  status: 200,
  json: async () => body,
});

afterEach(() => vi.unstubAllGlobals());

describe('InviteAcceptanceForm', () => {
  it('sets the password after validation and clears the password fields', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ valid: true }))
      .mockResolvedValueOnce(jsonResponse({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    render(<InviteAcceptanceForm token={token} tenantSlug="sentinel-demo" />);
    await screen.findByLabelText('Password');
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'safe-password-123' } });
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'safe-password-123' } });
    fireEvent.click(screen.getByRole('button', { name: 'Set password' }));

    expect(await screen.findByText(/Your administrator account is ready/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      token,
      tenant: 'sentinel-demo',
      password: 'safe-password-123',
    });
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
  });

  it('shows the same generic message for an invalid invitation', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ valid: false })));
    render(<InviteAcceptanceForm token={token} tenantSlug="sentinel-demo" />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid, expired, or already used/i);
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
  });

  it('does not submit when password confirmation differs', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({ valid: true }));
    vi.stubGlobal('fetch', fetchMock);
    render(<InviteAcceptanceForm token={token} tenantSlug="sentinel-demo" />);
    await screen.findByLabelText('Password');
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'safe-password-123' } });
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'different-pass-123' } });
    fireEvent.click(screen.getByRole('button', { name: 'Set password' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Passwords do not match.'));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('shows a generic message when redemption fails', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ valid: true }))
      .mockResolvedValueOnce({ ok: false, status: 400, json: async () => ({ detail: 'ignored' }) });
    vi.stubGlobal('fetch', fetchMock);
    render(<InviteAcceptanceForm token={token} tenantSlug="sentinel-demo" />);
    await screen.findByLabelText('Password');
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'safe-password-123' } });
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'safe-password-123' } });
    fireEvent.click(screen.getByRole('button', { name: 'Set password' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid, expired, or already used/i);
    expect(screen.queryByText('ignored')).not.toBeInTheDocument();
  });
});
