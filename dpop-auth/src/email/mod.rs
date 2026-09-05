//! Email delivery abstraction (feature `email`).

use std::pin::Pin;

use thiserror::Error;

/// A boxed, `Send` future returned by [`EmailSender::send`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Errors raised while building or sending an email.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EmailError {
    /// The email could not be built (bad address or headers).
    #[error("failed to build email: {0}")]
    Build(String),

    /// The email could not be send over the transport.
    #[error("failed to send email: {0}")]
    Send(String),

    /// An internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for EmailError {
    fn from(value: sqlx::Error) -> Self {
        EmailError::Internal(value.to_string())
    }
}

/// An asynchronous email sender.
///
/// The library never depends on a concrete transport. Applications typically use:
///
/// * **[`SmtpEmailSender`]** - In production.
/// * **[`LogEmailSender`]** - In development.
/// * **[`StubEmailSender`]** - In tests.
/// * A custom implementation tailored to specific infrastructure.
pub trait EmailSender: Send + Sync {
    /// Send a plain-text email.
    fn send<'a>(
        &'a self,
        to: &'a str,
        subject: &'a str,
        body: &'a str,
    ) -> BoxFuture<'a, Result<(), EmailError>>;
}

/// SMTP connection settings for [`SmtpEmailSender`].
#[derive(Clone)]
pub struct SmtpConfig {
    /// SMTP server host.
    pub host: String,
    /// SMTP server port (587 for STARTTLS, 25/1025 for plain relay).
    pub port: u16,
    /// Optional SMTP username.
    pub username: Option<String>,
    /// Optional SMTP password.
    pub password: Option<String>,
    /// Sender display name.
    pub from_name: String,
    /// Sender email address.
    pub from_email: String,
    /// Whether to use STARTTLS.
    pub starttls: bool,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &["REDACTED"])
            .field("from_name", &self.from_name)
            .field("from_email", &self.from_email)
            .field("starttls", &self.starttls)
            .finish()
    }
}

/// Sends email over SMTP using lettre.
pub struct SmtpEmailSender {
    mailer: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: lettre::message::Mailbox,
}

impl SmtpEmailSender {
    /// Build a sender from [`SmtpConfig`].
    pub fn from_config(config: &SmtpConfig) -> Result<Self, EmailError> {
        use lettre::message::Mailbox;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::transport::smtp::client::Tls;
        use lettre::{AsyncSmtpTransport, Tokio1Executor};

        let from = if config.from_name.is_empty() {
            config.from_email.parse::<Mailbox>()
        } else {
            let address = config
                .from_email
                .parse()
                .map_err(|e: lettre::address::AddressError| EmailError::Build(e.to_string()))?;

            Ok(Mailbox::new(Some(config.from_name.clone()), address))
        }
        .map_err(|e| EmailError::Build(e.to_string()))?;

        let mut builder = if config.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|e| EmailError::Build(format!("invalid SMTP relay host: {e}")))?
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host).tls(Tls::None)
        };

        builder = builder.port(config.port);

        if let (Some(username), Some(password)) = (&config.username, &config.password) {
            builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
        };

        Ok(Self {
            mailer: builder.build(),
            from,
        })
    }
}

impl EmailSender for SmtpEmailSender {
    fn send<'a>(
        &'a self,
        to: &'a str,
        subject: &'a str,
        body: &'a str,
    ) -> BoxFuture<'a, Result<(), EmailError>> {
        Box::pin(async move {
            use lettre::message::Mailbox;
            use lettre::message::header::ContentType;
            use lettre::{AsyncTransport, Message};

            let to_mailbox = to
                .parse::<Mailbox>()
                .map_err(|e| EmailError::Build(e.to_string()))?;

            let email = Message::builder()
                .from(self.from.clone())
                .to(to_mailbox)
                .subject(subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body.to_string())
                .map_err(|e| EmailError::Build(e.to_string()))?;

            self.mailer
                .send(email)
                .await
                .map_err(|e| EmailError::Send(e.to_string()))?;

            Ok(())
        })
    }
}

/// Logs email instead of sending them (development).
#[derive(Debug, Clone, Copy, Default)]
pub struct LogEmailSender;

impl EmailSender for LogEmailSender {
    fn send<'a>(
        &'a self,
        to: &'a str,
        subject: &'a str,
        body: &'a str,
    ) -> BoxFuture<'a, Result<(), EmailError>> {
        tracing::info!(
            to = %to,
            subject =  %subject,
            body = %body,
            "email dispatched"
        );

        Box::pin(std::future::ready(Ok(())))
    }
}

/// A captured email message for inspection in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentEmail {
    /// Recipient address.
    pub to: String,
    /// Email subject.
    pub subject: String,
    /// Email plain-text body.
    pub body: String,
}

/// Records sent emails in memory (tests).
#[derive(Debug, Default)]
pub struct StubEmailSender {
    sent: std::sync::Mutex<Vec<SentEmail>>,
}

impl StubEmailSender {
    /// Create a new empty stub sender.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of recorded messages.
    pub fn messages(&self) -> Vec<SentEmail> {
        self.sent.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Number of recorded messages without cloning string data.
    pub fn count(&self) -> usize {
        self.sent.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Clear all captured messages.
    pub fn clear(&self) {
        self.sent.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

impl EmailSender for StubEmailSender {
    fn send<'a>(
        &'a self,
        to: &'a str,
        subject: &'a str,
        body: &'a str,
    ) -> BoxFuture<'a, Result<(), EmailError>> {
        self.sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(SentEmail {
                to: to.to_string(),
                subject: subject.to_string(),
                body: body.to_string(),
            });

        Box::pin(std::future::ready(Ok(())))
    }
}
