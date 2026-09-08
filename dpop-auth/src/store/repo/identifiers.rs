//! Identifier persistence and lookup queries.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::store::models::{IdentifierRow, UserRow};

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
            u.totp_pending_secret,
			u.totp_pending_at,
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

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    use crate::store::repo::users as repo_users;

    use super::*;

    async fn create_test_user(conn: &mut PgConnection, email: &str) -> UserRow {
        let user = repo_users::create_user(conn, "Test User", "hash", Some(Utc::now()))
            .await
            .unwrap();

        create_identifier(conn, user.id, "email", email, true, Some(Utc::now()))
            .await
            .unwrap();

        user
    }

    #[sqlx::test]
    async fn create_identifier_and_find_by_identifier(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = repo_users::create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
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
        let user = repo_users::create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
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
}
