//! Login-attempt audit and anti-bruteforce queries.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, types::ipnetwork::IpNetwork};

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
    use std::net::IpAddr;

    use sqlx::PgPool;
    use sqlx::types::ipnetwork::IpNetwork;

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
