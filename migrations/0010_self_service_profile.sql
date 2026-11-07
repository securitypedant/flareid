-- Self-service profile editing: which schema attributes a user may change on
-- their own account page. Off for everything by default, and refused for any
-- attribute a dynamic group's rule matches on - otherwise editing a field
-- would let a user put themselves into a group.
ALTER TABLE schema_attributes ADD COLUMN user_editable INTEGER NOT NULL DEFAULT 0;
