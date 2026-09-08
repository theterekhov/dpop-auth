//! Refresh-token persistence, rotation, and revocation queries.

use sqlx::PgConnection;
use uuid::Uuid;

use crate::store::models::{CreateRefreshTokenParams, RefreshTokenRow};

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

/// Atomically revoke a refresh token if it is still active (`revoked_at IS NULL`).
///
/// Returns the revoked row on success. Returns `None` if the token was already
/// revoked or does not exist - the caller inspects the original row
/// (via a separate query) to distinguish grace from reuse.
pub async fn revoke_refresh_token_if_active(
    conn: &mut PgConnection,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        RefreshTokenRow,
        r#"
		UPDATE dpop_refresh_tokens SET revoked_at = now()
		WHERE token_hash = $1
			AND revoked_at IS NULL
		RETURNING
			id,
			user_id,
			token_hash,
			fam,
			dpop_jkt,
			user_agent,
			expires_at,
			created_at,
			revoked_at
		"#,
        token_hash
    )
    .fetch_optional(conn)
    .await
}

/// Revoke a refresh token by its hash (idempotent).
pub async fn revoke_refresh_token_by_hash(
    conn: &mut PgConnection,
    token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_refresh_tokens SET revoked_at = now()
		WHERE token_hash = $1
			AND revoked_at IS NULL
		"#,
        token_hash
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

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sqlx::PgPool;

    use super::*;

    use crate::store::repo::users as repo_users;

    #[sqlx::test]
    async fn create_refresh_token_and_find_by_hash(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let user = repo_users::create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
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
        let user = repo_users::create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
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
        let user = repo_users::create_user(&mut conn, "Alice", "hash", Some(Utc::now()))
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
