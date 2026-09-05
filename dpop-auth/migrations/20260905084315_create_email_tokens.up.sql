-- Add up migration script here
-- TABLE
CREATE TABLE dpop_email_tokens (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	user_id UUID NOT NULL REFERENCES dpop_users(id) ON DELETE CASCADE,
	kind VARCHAR(32) NOT NULL CHECK (kind IN ('verification', 'reset', 'change')),
	token_hash TEXT NOT NULL UNIQUE,
	new_email VARCHAR(255),
	expires_at TIMESTAMPTZ NOT NULL,
	used_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- INDEXES
CREATE INDEX idx_dpop_email_tokens_user_active
	ON dpop_email_tokens (user_id, kind)
	WHERE used_at IS NULL;

CREATE INDEX idx_dpop_email_tokens_expires
	ON dpop_email_tokens (expires_at);
