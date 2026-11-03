-- "Bare" becomes "Basic", and the default schema is a flag rather than a name.
--
-- 0004 found the default by name, which meant renaming it in the admin UI
-- would silently leave new objects with no schema. is_default carries the
-- role instead; exactly one row per object type has it.
ALTER TABLE schemas ADD COLUMN is_default INTEGER NOT NULL DEFAULT 0;

UPDATE schemas SET name = 'Basic', is_default = 1 WHERE name = 'Bare' AND builtin = 1;
UPDATE schemas SET description = 'Minimum viable identity: username and name only.' WHERE object_type = 'user' AND name = 'Basic';
UPDATE schemas SET description = 'Minimum viable group: name and description only.' WHERE object_type = 'group' AND name = 'Basic';

-- Dynamic groups no longer take explicit members: membership is the rule's
-- matches and nothing else. Clear any rows a dynamic group picked up before
-- that was enforced.
DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE rule != '');
