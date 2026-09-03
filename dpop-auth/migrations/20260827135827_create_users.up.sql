-- Add up migration script here
-- FUNCTION
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger AS $$
BEGIN
	NEW.updated_at = now();
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- USERS
-- TABLE
CREATE TABLE dpop_users (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	public_id UUID NOT NULL DEFAULT uuidv4() UNIQUE,
	password_hash TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	password_changed_at TIMESTAMPTZ,
	totp_secret VARCHAR(64),
	totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
	totp_enabled_at TIMESTAMPTZ,
	totp_pending_secret TEXT,
	totp_pending_at TIMESTAMPTZ,
	last_login_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	deleted_at TIMESTAMPTZ
);

-- INDEX
CREATE INDEX idx_dpop_users_created
	ON dpop_users (created_at DESC)
	WHERE deleted_at IS NULL;

-- TRIGGER
CREATE TRIGGER trg_dpop_users_updated
	BEFORE UPDATE ON dpop_users
	FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- IDENTIFIERS
-- TABLE
CREATE TABLE dpop_identifiers (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	user_id UUID NOT NULL REFERENCES dpop_users(id) ON DELETE CASCADE,
	kind VARCHAR(32) NOT NULL, -- examples: email, login, phone and etc.
	value VARCHAR(255) NOT NULL,
	is_primary BOOLEAN NOT NULL DEFAULT FALSE,
	verified_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	deleted_at TIMESTAMPTZ
);

-- INDEXES
CREATE UNIQUE INDEX uq_dpop_identifiers_kind_value
	ON dpop_identifiers (kind, LOWER(value))
	WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_dpop_identifiers_user_primary
	ON dpop_identifiers (user_id, kind)
	WHERE is_primary = TRUE AND deleted_at IS NULL;

CREATE INDEX idx_dpop_identifiers_user
	ON dpop_identifiers (user_id)
	WHERE deleted_at IS NULL;

-- TRIGGER
CREATE TRIGGER trg_dpop_identifiers_updated
	BEFORE UPDATE ON dpop_identifiers
	FOR EACH ROW EXECUTE FUNCTION set_updated_at();
