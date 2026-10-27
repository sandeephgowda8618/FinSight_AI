BEGIN;

-- Preserve the actor UUID and prevent hard deletion from mutating history.
ALTER TABLE audit_events
    DROP CONSTRAINT audit_events_actor_user_id_fkey;

ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_actor_user_id_fkey
    FOREIGN KEY (actor_user_id)
    REFERENCES users(user_id)
    ON DELETE RESTRICT;

-- Audit events are append-only. Corrections must be represented by new events.
CREATE FUNCTION reject_audit_events_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only; % is not permitted', TG_OP
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW
EXECUTE FUNCTION reject_audit_events_mutation();

COMMIT;
