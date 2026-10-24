//! MIME, file-type and archive parsing. The worker process calls these
//! functions. They must not panic on hostile input.
pub mod archive;
pub mod external;
pub mod filetype;
pub mod fuzz;
pub mod html_smuggling;
pub mod ipc;
pub mod office;
pub mod onenote;
pub mod parse;
pub mod pdf;
pub mod qr;
pub mod sandbox;
pub mod shortcut;
pub mod svg;
pub mod text;
pub mod yara;

pub use ipc::{FoundUrl, LoadRules, ParseRequest, ParseResponse, UrlSource};
pub use parse::parse_request;
