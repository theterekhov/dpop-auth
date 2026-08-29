//! Data-access layer over `PgConnection`.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, types::ipnetwork::IpNetwork};
use uuid::Uuid;

use crate::store::models::{CreateRefreshTokenParams, IdentifierRow, RefreshTokenRow, UserRow};

/// Create a user with a password hash and an optional `password_changed_at`.
pub async fn create_user(
    conn: &mut PgConnection,
    name: &str,
    password_hash: &str,
    password_changed_at: Option<DateTime<Utc>>,
) -> Result<UserRow, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        r#"
		INSERT INTO dpop_users (
			password_hash,
			name,
			password_changed_at
		) VALUES ($1, $2, $3)
		RETURNING
			id,
			public_id,
			password_hash,
			name,
			password_changed_at,
			totp_secret,
			totp_enabled,
			totp_enabled_at,
			last_login_at,
			created_at,
			updated_at,
			deleted_at
		"#,
        password_hash,
        name,
        password_changed_at
    )
    .fetch_one(conn)
    .await
}

/// Create a login identifier for a user.
///
/// `value` is normalized to lowercase before insert
/// (the UNIQUE index on `LOWER(value)` remains as defense-in-depth).
pub async fn create_identifier(
    conn: &mut PgConnection,
    user_id: Uuid,
    kind: &str,
    value: &str,
    is_primary: bool,
    verified_at: Option<DateTime<Utc>>,
) -> Result<IdentifierRow, sqlx::Error> {
    let value = value.to_lowercase();

    sqlx::query_as!(
        IdentifierRow,
        r#"
      	INSERT INTO dpop_identifiers (
       		user_id,
         	kind,
          	value,
           	is_primary,
            verified_at
       	) VALUES ($1, $2, $3, $4, $5)
        RETURNING
        	id,
         	user_id,
          	kind,
           	value,
            is_primary,
            verified_at,
            created_at,
            updated_at,
            deleted_at
      	"#,
        user_id,
        kind,
        value,
        is_primary,
        verified_at
    )
    .fetch_one(conn)
    .await
}

/// Resolve a user by login identifier (`kind` + `value`).
///
/// The lookup is case-insensitive: `value` is normalized to lowercase and
/// compare against `LOWER(i.value)` (which matches the expression index).
pub async fn find_user_by_identifier(
    conn: &mut PgConnection,
    kind: &str,
    value: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    let value = value.to_lowercase();

    sqlx::query_as!(
        UserRow,
        r#"
      	SELECT
       		u.id,
         	u.public_id,
          	u.password_hash,
           	u.name,
            u.password_changed_at,
            u.totp_secret,
            u.totp_enabled,
            u.totp_enabled_at,
            u.last_login_at,
            u.created_at,
            u.updated_at,
            u.deleted_at
        FROM dpop_users u
        JOIN dpop_identifiers i ON i.user_id = u.id
        WHERE i.kind = $1
        	AND LOWER(i.value) = $2
         	AND i.deleted_at IS NULL
          	AND u.deleted_at IS NULL
      	"#,
        kind,
        value
    )
    .fetch_optional(conn)
    .await
}

/// Find a user by internal id.
pub async fn find_user_by_id(
    conn: &mut PgConnection,
    id: Uuid,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        r#"
		SELECT
			id,
			public_id,
			password_hash,
			name,
			password_changed_at,
			totp_secret,
			totp_enabled,
			totp_enabled_at,
			last_login_at,
			created_at,
			updated_at,
			deleted_at
		FROM dpop_users
		WHERE id = $1 AND deleted_at IS NULL
		"#,
        id
    )
    .fetch_optional(conn)
    .await
}

/// Find a user by public id.
pub async fn find_user_by_public_id(
    conn: &mut PgConnection,
    public_id: Uuid,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        r#"
		SELECT
			id,
			public_id,
			password_hash,
			name,
			password_changed_at,
			totp_secret,
			totp_enabled,
			totp_enabled_at,
			last_login_at,
			created_at,
			updated_at,
			deleted_at
		FROM dpop_users
		WHERE public_id = $1 AND deleted_at IS NULL
		"#,
        public_id
    )
    .fetch_optional(conn)
    .await
}

/// Update the last login timestamp.
pub async fn update_last_login_at(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_users SET last_login_at = now()
		WHERE id = $1
		"#,
        user_id
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Update a user's password hash and mark it changed.
pub async fn update_password(
    conn: &mut PgConnection,
    user_id: Uuid,
    password_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_users SET
			password_hash = $2,
			password_changed_at = now()
		WHERE id = $1 AND deleted_at IS NULL
		"#,
        user_id,
        password_hash
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Insert a refresh token (only its hash is stored).
pub async fn create_refresh_token(
    conn: &mut PgConnection,
    params: CreateRefreshTokenParams,
) -> Result<RefreshTokenRow, sqlx::Error> {
    sqlx::query_as!(
        RefreshTokenRow,
        r#"
        INSERT INTO dpop_refresh_tokens (
        	user_id,
         	token_hash,
          	fam,
           	dpop_jkt,
            user_agent,
            expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING
        	id,
         	user_id,
          	token_hash,
           	fam,
            dpop_jkt,
            user_agent,
            expires_at,
            revoked_at,
            created_at
        "#,
        params.user_id,
        params.token_hash,
        params.fam,
        params.dpop_jkt,
        params.user_agent,
        params.expires_at
    )
    .fetch_one(conn)
    .await
}

/// Find a refresh token by its hash.
pub async fn find_refresh_token_by_hash(
    conn: &mut PgConnection,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        RefreshTokenRow,
        r#"
		SELECT
			id,
			user_id,
			token_hash,
			fam,
			dpop_jkt,
			user_agent,
			expires_at,
			revoked_at,
			created_at
		FROM dpop_refresh_tokens
		WHERE token_hash = $1
		"#,
        token_hash
    )
    .fetch_optional(conn)
    .await
}

/// Revoke a single refresh token by internal id.
pub async fn revoke_refresh_token(conn: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_refresh_tokens SET revoked_at = now()
		WHERE id = $1 AND revoked_at IS NULL
		"#,
        id
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Revoke an entire refresh_token family (reuse detection).
pub async fn revoke_refresh_token_family(
    conn: &mut PgConnection,
    fam: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_refresh_tokens SET revoked_at = now()
		WHERE fam = $1 AND revoked_at IS NULL
		"#,
        fam
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Revoke every refresh token of a user.
pub async fn revoke_all_refresh_tokens_for_user(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_refresh_tokens SET revoked_at = now()
		WHERE user_id = $1 AND revoked_at IS NULL
		"#,
        user_id
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Record a login attempt (audit log, `identifier_value` normalized to lowercase).
pub async fn record_login_attempt(
    conn: &mut PgConnection,
    identifier_kind: &str,
    identifier_value: &str,
    ip_address: IpNetwork,
    success: bool,
    failure_reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    let identifier_value = identifier_value.to_lowercase();

    sqlx::query!(
        r#"
		INSERT INTO dpop_login_attempts (
			identifier_kind,
			identifier_value,
			ip_address,
			success,
			failure_reason
		) VALUES ($1, $2, $3, $4, $5)
		"#,
        identifier_kind,
        identifier_value,
        ip_address,
        success,
        failure_reason
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Count failed login attempts since `since` (anti-bruteforce / rate-limiting).
pub async fn count_recent_failed_attempts(
    conn: &mut PgConnection,
    identifier_kind: &str,
    identifier_value: &str,
    since: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    let identifier_value = identifier_value.to_lowercase();

    sqlx::query_scalar!(
        r#"
		SELECT COUNT(*) as "count!"
		FROM dpop_login_attempts
		WHERE identifier_kind = $1
			AND LOWER(identifier_value) = $2
			AND success = false
			AND created_at >= $3
		"#,
        identifier_kind,
        identifier_value,
        since
    )
    .fetch_one(conn)
    .await
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    use super::*;

    async fn create_test_user(conn: &mut PgConnection, email: &str) -> UserRow {
        let user = create_user(conn, "Test User", "hash", Some(Utc::now()))
            .await
            .unwrap();

        create_identifier(conn, user.id, "email", email, true, Some(Utc::now()))
            .await
            .unwrap();

        user
    }

    #[sqlx::test]
    async fn create_user_and_find_by_id(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = create_user(&mut conn, "Alice", "hash", None).await.unwrap();

        assert_eq!(user.name, "Alice");
        assert!(user.password_changed_at.is_none());

        let found = find_user_by_id(&mut conn, user.id).await.unwrap().unwrap();
        assert_eq!(found.id, user.id);
        assert_eq!(found.public_id, user.public_id);
    }

    #[sqlx::test]
    async fn create_identifier_and_find_by_identifier(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
            .await
            .unwrap();

        create_identifier(
            &mut conn,
            user.id,
            "email",
            "Alice@Example.com",
            true,
            Some(Utc::now()),
        )
        .await
        .unwrap();

        let found = find_user_by_identifier(&mut conn, "email", "alice@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, user.id);
    }

    #[sqlx::test]
    async fn find_by_identifier_is_case_insensitive(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        create_test_user(&mut conn, "User@Example.com").await;

        let found = find_user_by_identifier(&mut conn, "email", "user@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name, "Test User");

        let missing = find_user_by_identifier(&mut conn, "email", "nobody@example.com")
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[sqlx::test]
    async fn identifiers_distinguish_kind(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
            .await
            .unwrap();

        create_identifier(
            &mut conn,
            user.id,
            "email",
            "alice@example.com",
            true,
            Some(Utc::now()),
        )
        .await
        .unwrap();
        create_identifier(&mut conn, user.id, "username", "alice", false, None)
            .await
            .unwrap();

        let by_email = find_user_by_identifier(&mut conn, "email", "alice@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_email.id, user.id);

        let by_username = find_user_by_identifier(&mut conn, "username", "alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_username.id, user.id);

        let wrong_kind = find_user_by_identifier(&mut conn, "phone", "alice")
            .await
            .unwrap();
        assert!(wrong_kind.is_none());
    }

    #[sqlx::test]
    async fn update_password_marks_changed(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = create_user(&mut conn, "ALice", "old", None).await.unwrap();
        assert!(user.password_changed_at.is_none());

        update_password(&mut conn, user.id, "new").await.unwrap();

        let updated = find_user_by_id(&mut conn, user.id).await.unwrap().unwrap();
        assert_eq!(updated.password_hash, "new");
        assert!(updated.password_changed_at.is_some());
    }

    #[sqlx::test]
    async fn create_refresh_token_and_find_by_hash(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
            .await
            .unwrap();

        let fam = Uuid::new_v4();
        let row = create_refresh_token(
            &mut conn,
            CreateRefreshTokenParams {
                user_id: user.id,
                token_hash: "abc".to_string(),
                fam,
                dpop_jkt: "jkt".to_string(),
                user_agent: None,
                expires_at: Utc::now() + chrono::Duration::days(30),
            },
        )
        .await
        .unwrap();

        assert_eq!(row.fam, fam);
        assert!(row.revoked_at.is_none());

        let found = find_refresh_token_by_hash(&mut conn, "abc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, row.id);
    }

    #[sqlx::test]
    async fn revoke_tokens_sets_revoked_at(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
            .await
            .unwrap();
        let row = create_refresh_token(
            &mut conn,
            CreateRefreshTokenParams {
                user_id: user.id,
                token_hash: "abc".to_string(),
                fam: Uuid::new_v4(),
                dpop_jkt: "jkt".to_string(),
                user_agent: None,
                expires_at: Utc::now() + chrono::Duration::days(30),
            },
        )
        .await
        .unwrap();

        revoke_refresh_token(&mut conn, row.id).await.unwrap();

        let found = find_refresh_token_by_hash(&mut conn, "abc")
            .await
            .unwrap()
            .unwrap();
        assert!(found.revoked_at.is_some());
    }

    #[sqlx::test]
    async fn revoke_family_revokes_all(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
            .await
            .unwrap();
        let fam = Uuid::new_v4();

        for i in 0..2 {
            create_refresh_token(
                &mut conn,
                CreateRefreshTokenParams {
                    user_id: user.id,
                    token_hash: format!("hash-{i}"),
                    fam,
                    dpop_jkt: "jkt".to_string(),
                    user_agent: None,
                    expires_at: Utc::now() + chrono::Duration::days(30),
                },
            )
            .await
            .unwrap();
        }

        revoke_refresh_token_family(&mut conn, fam).await.unwrap();

        for i in 0..2 {
            let found = find_refresh_token_by_hash(&mut conn, &format!("hash-{i}"))
                .await
                .unwrap()
                .unwrap();

            assert!(found.revoked_at.is_some());
        }
    }
}

#[cfg(test)]
mod tests_login_attempts {
    use std::net::IpAddr;

    use sqlx::PgPool;

    use super::*;

    #[sqlx::test]
    async fn record_login_attempt_and_count_failed(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let ip: IpNetwork = "203.0.133.7".parse::<IpAddr>().unwrap().into();
        let since = Utc::now() - chrono::Duration::minutes(5);

        record_login_attempt(
            &mut conn,
            "email",
            "User@EXAMPLE.com",
            ip,
            false,
            Some("wrong_password"),
        )
        .await
        .unwrap();
        record_login_attempt(
            &mut conn,
            "email",
            "user@example.com",
            ip,
            false,
            Some("wrong_password"),
        )
        .await
        .unwrap();
        record_login_attempt(&mut conn, "email", "user@example.com", ip, true, None)
            .await
            .unwrap();

        let count = count_recent_failed_attempts(&mut conn, "email", "user@example.com", since)
            .await
            .unwrap();
        assert_eq!(count, 2);
    }

    #[sqlx::test]
    async fn count_recent_failed_respects_windows(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let ip: IpNetwork = "203.0.113.7".parse::<IpAddr>().unwrap().into();

        record_login_attempt(
            &mut conn,
            "email",
            "user@example.com",
            ip,
            false,
            Some("wrong"),
        )
        .await
        .unwrap();

        // window includes the attempt
        let past = Utc::now() - chrono::Duration::hours(1);
        let count = count_recent_failed_attempts(&mut conn, "email", "user@example.com", past)
            .await
            .unwrap();
        assert_eq!(count, 1);

        // window in the future excludes the attempt
        let future = Utc::now() + chrono::Duration::hours(1);
        let count = count_recent_failed_attempts(&mut conn, "email", "user@example.com", future)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
