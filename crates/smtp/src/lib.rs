//! SMTP server, connection checks and outbound delivery.
pub mod auth_sasl;
pub mod checks;
pub mod command;
pub mod data;
pub mod delivery;
pub mod dns;
pub mod fuzz;
pub mod limits;
pub mod relay;
pub mod server;
pub mod session;
pub mod stream;
pub mod tls;
pub mod tlsrpt;

pub use currawong_core::Error;
pub use server::SmtpServer;
pub use session::{run_session, SessionContext};
