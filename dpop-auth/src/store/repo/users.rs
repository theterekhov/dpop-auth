//! User persistence: create, lookup, and update queries.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::store::models::UserRow;

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
			totp_pending_secret,
			totp_pending_at,
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
			totp_pending_secret,
			totp_pending_at,
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
			totp_pending_secret,
			totp_pending_at,
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

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    use super::*;

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
    async fn update_password_marks_changed(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = create_user(&mut conn, "ALice", "old", None).await.unwrap();
        assert!(user.password_changed_at.is_none());

        update_password(&mut conn, user.id, "new").await.unwrap();

        let updated = find_user_by_id(&mut conn, user.id).await.unwrap().unwrap();
        assert_eq!(updated.password_hash, "new");
        assert!(updated.password_changed_at.is_some());
    }
}
