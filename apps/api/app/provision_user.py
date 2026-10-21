"""Create or update a user from a trusted local administrator shell."""

from __future__ import annotations

import getpass
import sys

from app.auth import hash_password
from app.database import connect


def main() -> int:
    if len(sys.argv) not in {3, 4} or (len(sys.argv) == 4 and sys.argv[3] != "--platform-admin"):
        print("Usage: python -m app.provision_user EMAIL DISPLAY_NAME [--platform-admin]", file=sys.stderr)
        return 2
    email, display_name = sys.argv[1].strip().lower(), sys.argv[2].strip()
    if not email or len(email) > 320 or not display_name or len(display_name) > 160:
        print("Email and display name are required and must fit the identity schema.", file=sys.stderr)
        return 2
    password = getpass.getpass("Initial password (hidden): ")
    confirmation = getpass.getpass("Confirm password (hidden): ")
    if password != confirmation or not password:
        print("Passwords did not match or were empty.", file=sys.stderr)
        return 2
    password_hash = hash_password(password)
    role_key = "platform_admin" if len(sys.argv) == 4 else None
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO users (email, password_hash, display_name, account_status, platform_role_id)
               VALUES (%s, %s, %s, 'active',
                       (SELECT role_id FROM roles WHERE role_key = %s AND scope = 'platform'))
               ON CONFLICT ((lower(email))) DO UPDATE SET
                   password_hash = EXCLUDED.password_hash,
                   display_name = EXCLUDED.display_name,
                   platform_role_id = COALESCE(EXCLUDED.platform_role_id, users.platform_role_id),
                   account_status = 'active', updated_at = now(), deleted_at = NULL""",
            (email, password_hash, display_name, role_key),
        )
    label = " with platform administrator permission" if role_key else " without platform permissions"
    print(f"User provisioned{label}. No password value was displayed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
