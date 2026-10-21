-- FIN-15: only the platform-scoped administrator permission is implemented.
-- Workspace roles and workspace permissions remain unavailable until workspace membership exists.
BEGIN;

CREATE TABLE permissions (
    permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permission_key VARCHAR(120) NOT NULL UNIQUE,
    description TEXT NOT NULL
);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

INSERT INTO roles (role_key, display_name, scope, description)
VALUES ('platform_admin', 'Platform Administrator', 'platform',
        'Administrator privileges for currently implemented platform operations only.')
ON CONFLICT (role_key) DO NOTHING;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM roles WHERE role_key = 'platform_admin' AND scope = 'platform') THEN
        RAISE EXCEPTION 'Existing platform_admin role has non-platform scope';
    END IF;
END
$$;

INSERT INTO permissions (permission_key, description)
VALUES ('platform.admin', 'Access operations explicitly assigned platform administrator permission.')
ON CONFLICT (permission_key) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r CROSS JOIN permissions p
WHERE r.role_key = 'platform_admin' AND r.scope = 'platform'
  AND p.permission_key = 'platform.admin'
ON CONFLICT DO NOTHING;

CREATE FUNCTION enforce_platform_role_scope() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.platform_role_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM roles WHERE role_id = NEW.platform_role_id AND scope = 'platform'
    ) THEN
        RAISE EXCEPTION 'platform_role_id must reference a platform-scoped role'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER users_platform_role_scope_check
BEFORE INSERT OR UPDATE OF platform_role_id ON users
FOR EACH ROW EXECUTE FUNCTION enforce_platform_role_scope();

CREATE FUNCTION prevent_platform_role_scope_drift() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.scope = 'platform' AND NEW.scope <> 'platform' AND EXISTS (
        SELECT 1 FROM users WHERE platform_role_id = OLD.role_id
    ) THEN
        RAISE EXCEPTION 'Cannot change scope of an assigned platform role';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER roles_prevent_scope_drift
BEFORE UPDATE OF scope ON roles
FOR EACH ROW EXECUTE FUNCTION prevent_platform_role_scope_drift();

COMMIT;
