-- Dynamic groups and the end of built-in "All Employees".
--
-- groups.rule holds a JSON conditions object evaluated against user
-- attributes at read time - {"all":[{"field":"employment_type","op":"eq","value":"full_time"}]}.
-- Explicit membership (group_members) still exists alongside it; a group's
-- effective membership is the union. Evaluation lives in src/lib/groups.ts.
--
-- The seeded 'All Employees' row is removed: a bare install should have no
-- opinionated directory. Deployments that want it create it as a dynamic
-- group - e.g. employment_type = full_time - which is also stronger, because
-- membership then follows attribute changes instead of a one-time join.
--
-- 'Super Admins' stays: it is the authorization boundary for /admin, not a
-- directory convention.
ALTER TABLE groups ADD COLUMN rule TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN schema_id INTEGER;
ALTER TABLE groups ADD COLUMN schema_id INTEGER;
ALTER TABLE users ADD COLUMN custom_attributes TEXT NOT NULL DEFAULT '{}';
ALTER TABLE groups ADD COLUMN custom_attributes TEXT NOT NULL DEFAULT '{}';

DELETE FROM groups WHERE name = 'All Employees';

-- Directory schemas: named attribute definitions for object classes, applied
-- per user/group via schema_id. 'user' and 'group' object types; attributes
-- beyond the fixed columns live in each row's custom_attributes JSON.
CREATE TABLE schemas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_type TEXT NOT NULL CHECK (object_type IN ('user', 'group')),
  name TEXT NOT NULL,
  description TEXT,
  -- 1 for shipped schemas (bare default, FlareID HR): editable but not
  -- deletable, so a deployment always has something valid to apply.
  builtin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE (object_type, name)
);

CREATE TABLE schema_attributes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_id INTEGER NOT NULL REFERENCES schemas(id) ON DELETE CASCADE,
  -- The key stored in custom_attributes and (for known fields) the column or
  -- claim name it maps to.
  name TEXT NOT NULL,
  label TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'string' CHECK (type IN ('string', 'number', 'date', 'boolean', 'reference')),
  required INTEGER NOT NULL DEFAULT 0,
  -- For type 'reference': 'user' means the value is another user's external_id
  -- (manager-style), resolved at read time.
  ref_object TEXT,
  position INTEGER NOT NULL DEFAULT 0,
  UNIQUE (schema_id, name)
);

-- The bare minimum every object conforms to out of the box.
INSERT INTO schemas (object_type, name, description, builtin, created_at) VALUES
  ('user', 'Bare', 'Minimum viable identity: username and name only.', 1, CURRENT_TIMESTAMP),
  ('group', 'Bare', 'Minimum viable group: name and description only.', 1, CURRENT_TIMESTAMP),
  ('user', 'FlareID HR', 'The full built-in HR attribute set: job title, department, manager, employee number, hire date, employment status/type, location.', 1, CURRENT_TIMESTAMP);

INSERT INTO schema_attributes (schema_id, name, label, type, required, ref_object, position)
SELECT s.id,
       j.value ->> 'name',
       j.value ->> 'label',
       j.value ->> 'type',
       j.value -> 'required',
       j.value ->> 'ref_object',
       j.value -> 'position'
FROM schemas s,
json_each('[
  {"name":"job_title","label":"Job title","type":"string","required":0,"ref_object":null,"position":10},
  {"name":"department","label":"Department","type":"string","required":0,"ref_object":null,"position":20},
  {"name":"manager","label":"Manager","type":"reference","required":0,"ref_object":"user","position":30},
  {"name":"employee_number","label":"Employee number","type":"string","required":0,"ref_object":null,"position":40},
  {"name":"hire_date","label":"Hire date","type":"date","required":0,"ref_object":null,"position":50},
  {"name":"employment_status","label":"Employment status","type":"string","required":0,"ref_object":null,"position":60},
  {"name":"employment_type","label":"Employment type","type":"string","required":0,"ref_object":null,"position":70},
  {"name":"location","label":"Location","type":"string","required":0,"ref_object":null,"position":80}
]') j
WHERE s.object_type = 'user' AND s.name = 'FlareID HR';
