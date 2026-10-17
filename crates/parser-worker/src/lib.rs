//! MIME, file-type and archive parsing. The worker process calls these
//! functions. They must not panic on hostile input.
pub mod archive;
pub mod filetype;
pub mod fuzz;
pub mod ipc;
pub mod office;
pub mod parse;
pub mod yara;

pub use ipc::{ParseRequest, ParseResponse};
pub use parse::parse_request;
