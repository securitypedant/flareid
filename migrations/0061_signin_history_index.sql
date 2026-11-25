-- Sign-in history on /account/security reads a person's own login events
-- from audit_log by target (the identifier they typed) and by actor (LDAP
-- binds); without these it scans the whole log.
CREATE INDEX idx_audit_log_target ON audit_log(target, id);
CREATE INDEX idx_audit_log_actor ON audit_log(actor_user_id, id);
