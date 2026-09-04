-- Add up migration script here
-- TABLE
CREATE TABLE dpop_recovery_codes (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	user_id UUID NOT NULL REFERENCES dpop_users(id) ON DELETE CASCADE,
	code_hash TEXT NOT NULL,
	used_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- INDEXES
CREATE INDEX idx_dpop_rc_user
	ON dpop_recovery_codes (user_id);

CREATE UNIQUE INDEX uq_dpop_rc_user_active_code
	ON dpop_recovery_codes (user_id, code_hash)
	WHERE used_at IS NULL;
