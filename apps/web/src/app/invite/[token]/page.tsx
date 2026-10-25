import type { Metadata } from 'next';
import { InviteAcceptanceForm } from '@/components/auth/InviteAcceptanceForm';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export const metadata: Metadata = {
  title: 'Set up your administrator account',
  referrer: 'no-referrer',
  robots: { index: false, follow: false },
};

export default async function InvitePage({
  params,
  searchParams,
}: {
  params: Promise<{ token: string }>;
  searchParams: Promise<{ tenant?: string }>;
}) {
  const [{ token }, query] = await Promise.all([params, searchParams]);
  return <InviteAcceptanceForm token={token} tenantSlug={query.tenant ?? ''} />;
}
