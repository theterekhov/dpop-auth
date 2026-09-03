-- Add up migration script here
-- TABLE
CREATE TABLE dpop_refresh_tokens(
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	user_id UUID NOT NULL REFERENCES dpop_users(id) ON DELETE CASCADE,
	token_hash TEXT NOT NULL UNIQUE,
	fam UUID NOT NULL,
	dpop_jkt VARCHAR(64) NOT NULL,
	user_agent TEXT,
	expires_at TIMESTAMPTZ NOT NULL,
	revoked_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- INDEXES
CREATE INDEX idx_dpop_rt_user
	ON dpop_refresh_tokens (user_id)
	WHERE revoked_at IS NULL;

CREATE INDEX idx_dpop_rt_fam
	ON dpop_refresh_tokens (fam);

CREATE INDEX idx_dpop_rt_expires
	ON dpop_refresh_tokens (expires_at);
