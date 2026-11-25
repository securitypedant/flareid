-- Access history (account -> Access): every time a person is added to or
-- removed from a static group, or directly assigned to / unassigned from an
-- app. Triggers rather than code, because membership is written from ~20
-- places (console, API, SCIM in and out, CSV and directory import, Cloudflare
-- One sync, request approvals, JIT federation).
--
-- Not a foreign key to users: a user delete cascades into group_members, and
-- the trigger must not insert rows for a user that is going away - the
-- EXISTS guards skip them, and the cleanup trigger below removes the rest.
--
-- Replace-all membership writes (DELETE every member, re-INSERT the list) would
-- otherwise log remove+add for everyone who stayed: an INSERT that finds a
-- 'removed' row for the same pair from the last few seconds cancels it instead
-- of logging 'added'.

CREATE TABLE access_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  target_type TEXT NOT NULL CHECK (target_type IN ('group', 'oidc_app', 'saml_app')),
  target_id INTEGER NOT NULL,
  target_name TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL CHECK (action IN ('added', 'removed')),
  at TEXT NOT NULL
);
CREATE INDEX idx_access_history_user ON access_history(user_id, at);
CREATE INDEX idx_access_history_pair ON access_history(user_id, target_type, target_id, action, at);

CREATE TRIGGER trg_access_history_group_add AFTER INSERT ON group_members
BEGIN
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT NEW.user_id, 'group', NEW.group_id, COALESCE((SELECT name FROM groups WHERE id = NEW.group_id), ''), 'added', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE EXISTS (SELECT 1 FROM users WHERE id = NEW.user_id)
      AND NOT EXISTS (SELECT 1 FROM access_history h WHERE h.user_id = NEW.user_id AND h.target_type = 'group' AND h.target_id = NEW.group_id AND h.action = 'removed' AND h.at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-5 seconds'));
  DELETE FROM access_history
    WHERE user_id = NEW.user_id AND target_type = 'group' AND target_id = NEW.group_id AND action = 'removed' AND at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-5 seconds');
END;

CREATE TRIGGER trg_access_history_group_remove AFTER DELETE ON group_members
BEGIN
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT OLD.user_id, 'group', OLD.group_id, COALESCE((SELECT name FROM groups WHERE id = OLD.group_id), ''), 'removed', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE EXISTS (SELECT 1 FROM users WHERE id = OLD.user_id);
END;

CREATE TRIGGER trg_access_history_user_delete AFTER DELETE ON users
BEGIN
  DELETE FROM access_history WHERE user_id = OLD.id;
END;

CREATE TRIGGER trg_access_history_oidc_insert AFTER INSERT ON oauth_clients
BEGIN
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT j.value, 'oidc_app', NEW.id, NEW.name, 'added', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM json_each(CASE WHEN json_valid(NEW.assigned_users) THEN NEW.assigned_users ELSE '[]' END) j
    WHERE j.type = 'integer' AND EXISTS (SELECT 1 FROM users WHERE id = j.value);
END;

CREATE TRIGGER trg_access_history_oidc_update AFTER UPDATE OF assigned_users ON oauth_clients
BEGIN
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT j.value, 'oidc_app', NEW.id, NEW.name, 'added', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM json_each(CASE WHEN json_valid(NEW.assigned_users) THEN NEW.assigned_users ELSE '[]' END) j
    WHERE j.type = 'integer' AND EXISTS (SELECT 1 FROM users WHERE id = j.value)
      AND j.value NOT IN (SELECT value FROM json_each(CASE WHEN json_valid(OLD.assigned_users) THEN OLD.assigned_users ELSE '[]' END));
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT j.value, 'oidc_app', NEW.id, NEW.name, 'removed', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM json_each(CASE WHEN json_valid(OLD.assigned_users) THEN OLD.assigned_users ELSE '[]' END) j
    WHERE j.type = 'integer' AND EXISTS (SELECT 1 FROM users WHERE id = j.value)
      AND j.value NOT IN (SELECT value FROM json_each(CASE WHEN json_valid(NEW.assigned_users) THEN NEW.assigned_users ELSE '[]' END));
END;

CREATE TRIGGER trg_access_history_oidc_delete AFTER DELETE ON oauth_clients
BEGIN
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT j.value, 'oidc_app', OLD.id, OLD.name, 'removed', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM json_each(CASE WHEN json_valid(OLD.assigned_users) THEN OLD.assigned_users ELSE '[]' END) j
    WHERE j.type = 'integer' AND EXISTS (SELECT 1 FROM users WHERE id = j.value);
END;

CREATE TRIGGER trg_access_history_saml_insert AFTER INSERT ON saml_service_providers
BEGIN
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT j.value, 'saml_app', NEW.id, NEW.name, 'added', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM json_each(CASE WHEN json_valid(NEW.assigned_users) THEN NEW.assigned_users ELSE '[]' END) j
    WHERE j.type = 'integer' AND EXISTS (SELECT 1 FROM users WHERE id = j.value);
END;

CREATE TRIGGER trg_access_history_saml_update AFTER UPDATE OF assigned_users ON saml_service_providers
BEGIN
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT j.value, 'saml_app', NEW.id, NEW.name, 'added', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM json_each(CASE WHEN json_valid(NEW.assigned_users) THEN NEW.assigned_users ELSE '[]' END) j
    WHERE j.type = 'integer' AND EXISTS (SELECT 1 FROM users WHERE id = j.value)
      AND j.value NOT IN (SELECT value FROM json_each(CASE WHEN json_valid(OLD.assigned_users) THEN OLD.assigned_users ELSE '[]' END));
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT j.value, 'saml_app', NEW.id, NEW.name, 'removed', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM json_each(CASE WHEN json_valid(OLD.assigned_users) THEN OLD.assigned_users ELSE '[]' END) j
    WHERE j.type = 'integer' AND EXISTS (SELECT 1 FROM users WHERE id = j.value)
      AND j.value NOT IN (SELECT value FROM json_each(CASE WHEN json_valid(NEW.assigned_users) THEN NEW.assigned_users ELSE '[]' END));
END;

CREATE TRIGGER trg_access_history_saml_delete AFTER DELETE ON saml_service_providers
BEGIN
  INSERT INTO access_history (user_id, target_type, target_id, target_name, action, at)
    SELECT j.value, 'saml_app', OLD.id, OLD.name, 'removed', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM json_each(CASE WHEN json_valid(OLD.assigned_users) THEN OLD.assigned_users ELSE '[]' END) j
    WHERE j.type = 'integer' AND EXISTS (SELECT 1 FROM users WHERE id = j.value);
END;
