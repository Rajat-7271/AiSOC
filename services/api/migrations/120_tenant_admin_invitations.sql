-- Single-use invitations for the initial administrator of a managed tenant.
-- Only the SHA-256 digest of the high-entropy bearer token is stored.
CREATE TABLE IF NOT EXISTS tenant_admin_invitations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  CHAR(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_tenant_admin_invitations_tenant_user
    ON tenant_admin_invitations (tenant_id, user_id);

-- A replacement invite revokes the previous outstanding invite in the same
-- transaction; this index makes that invariant hold under concurrent issuance.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_admin_invitation_outstanding_user
    ON tenant_admin_invitations (tenant_id, user_id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

ALTER TABLE tenant_admin_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_admin_invitations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_admin_invitations_tenant ON tenant_admin_invitations;
CREATE POLICY tenant_admin_invitations_tenant ON tenant_admin_invitations
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMENT ON TABLE tenant_admin_invitations IS
    'Single-use initial-admin invitations. Raw bearer tokens are never stored.';
