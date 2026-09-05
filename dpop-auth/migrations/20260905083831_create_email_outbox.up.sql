-- Add up migration script here
-- TABLE
CREATE TABLE dpop_email_outbox (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	to_address VARCHAR(255) NOT NULL,
	subject TEXT NOT NULL,
	body TEXT NOT NULL,
	attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
	max_attempts SMALLINT NOT NULL DEFAULT 5 CHECK (max_attempts >= 0),
	last_error TEXT,
	available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	locked_at TIMESTAMPTZ,
	sent_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- INDEX
CREATE INDEX idx_dpop_outbox_queue
	ON dpop_email_outbox (available_at)
	WHERE sent_at IS NULL
		AND locked_at IS NULL
		AND attempts < max_attempts;
