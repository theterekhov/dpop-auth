-- Add down migration script here
-- IDENTIFIERS
DROP TABLE IF EXISTS dpop_identifiers;

-- USERS
DROP TABLE IF EXISTS dpop_users;

-- FUNCTION
DROP FUNCTION IF EXISTS set_updated_at();
