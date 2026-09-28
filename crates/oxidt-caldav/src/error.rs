/// Why a CalDAV request failed. The HTTP status is preserved; user-facing copy
/// is the app's to write.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A status with no variant of its own. `title` is the reason phrase.
    #[error("the server answered {code} {title}")]
    Status { code: u16, title: String },
    /// `401`: wrong username or app password.
    #[error("the server rejected the credentials")]
    Unauthorized,
    /// `404`, or no calendar home where discovery expected one.
    #[error("nothing found at that address")]
    NotFound,
    /// `412` where no precondition was expected to fail.
    #[error("the server refused a precondition")]
    PreconditionFailed,
    /// The URL exists but is not a WebDAV collection.
    #[error("that address is not a WebDAV collection")]
    NotACollection,
    #[error("could not reach the server: {0}")]
    Transport(#[source] reqwest::Error),
    /// The URL, or one the server sent, was refused by the egress policy.
    #[error(transparent)]
    Egress(#[from] oxidt_egress::Error),
    /// The server's multistatus answer could not be read.
    #[error("the server sent an unreadable answer")]
    Xml,
    /// A URL could not be built from the parts given.
    #[error("that address can't hold a calendar object")]
    Url,
}
