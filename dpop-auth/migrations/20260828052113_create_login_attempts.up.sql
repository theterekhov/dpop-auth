-- Add up migration script here
-- TABLE
CREATE TABLE dpop_login_attempts (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	identifier_kind VARCHAR(32) NOT NULL,
	identifier_value VARCHAR(255) NOT NULL,
	ip_address INET NOT NULL,
	success BOOLEAN NOT NULL,
	failure_reason TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- INDEXES
CREATE INDEX idx_dpop_login_ident
	ON dpop_login_attempts (identifier_kind, LOWER(identifier_value), created_at DESC);

CREATE INDEX idx_dpop_login_ip
	ON dpop_login_attempts (ip_address, created_at DESC);

CREATE INDEX idx_dpop_login_created
	ON dpop_login_attempts (created_at);
