//! Fresh email proof for one sensitive action (removing a passkey, deleting an
//! account, changing a payout address, ...).
//!
//! A logged-in session asks for a code. The code is mailed to the account's
//! current address and is bound to the action, user, session and target. It
//! expires and allows [`MAX_ATTEMPTS`] guesses, and it is spent in the same
//! transaction as the action it protects. The crate owns that protocol; the
//! app owns everything that touches its storage or its users, behind
//! [`ActionProofBackend`].
//!
//! No elevation token is ever handed out. A verified code authorizes exactly
//! the one [`ActionProofBackend::consume_and_perform`] call it was checked
//! for, and that call must delete the proof atomically with the action.
//! Process-local locks cannot provide that across replicas, so the atomicity
//! contracts on the trait are the security boundary, not a detail.

use std::time::Duration;

use crate::error::{AuthError, AuthResult};
use crate::session::UserSession;

/// How long a mailed code stays valid.
pub const CODE_TTL: Duration = Duration::from_secs(5 * 60);
/// Guesses one code allows, malformed ones included. A resend resets this, so
/// bound the total with [`ActionProofBackend::charge_guess`].
pub const MAX_ATTEMPTS: u32 = 5;
/// Length of the numeric code.
pub const CODE_DIGITS: usize = 6;

/// What a proof is for: one action, by one user, from one browser session, on
/// one target.
///
/// Built from the session only, so the user cannot come from request input. The
/// session part is a SHA-256 of the session id, so storing it reveals no cookie.
/// The built-in login handlers rotate the id, so a pending proof does not carry
/// over into the next login. [`crate::session::login`] alone does not rotate
/// it; a custom login must call `session.cycle_id()` itself. Build a binding
/// from the live session on every request and never cache it across requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionBinding {
    action: &'static str,
    user_id: String,
    session_key: String,
    target: String,
}

impl ActionBinding {
    /// Bind `action` on `target` to the logged-in user of `session`.
    ///
    /// `target` is whatever the app's action acts on (a passkey row id, an
    /// org id, `""` for the account itself). The app validates it, and
    /// [`ActionProofBackend::recipient`] checks that the user owns it.
    pub async fn from_session(
        session: &tower_sessions::Session,
        action: &'static str,
        target: impl Into<String>,
    ) -> AuthResult<Self> {
        let user = UserSession::from_session(session).await?.data()?;
        let id = session.id().ok_or(AuthError::UserNotLoggedIn)?;
        Ok(Self {
            action,
            user_id: user.id,
            session_key: crypto::hash_api_key(&id.to_string()),
            target: target.into(),
        })
    }

    pub fn action(&self) -> &'static str {
        self.action
    }

    /// The logged-in user (`AuthUser.id`).
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Opaque, stable for the session id it was derived from.
    pub fn session_key(&self) -> &str {
        &self.session_key
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}

/// A freshly minted proof, before and while its code is mailed.
#[derive(Debug)]
pub struct PendingActionProof {
    binding: ActionBinding,
    recipient: String,
    code_hash: String,
    ttl: Duration,
}

impl PendingActionProof {
    pub fn binding(&self) -> &ActionBinding {
        &self.binding
    }

    /// The account address [`ActionProofBackend::recipient`] resolved.
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Argon2 hash of the code. The plaintext is never stored.
    pub fn code_hash(&self) -> &str {
        &self.code_hash
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// A code that matched, handed to [`ActionProofBackend::consume_and_perform`]
/// and nowhere else. Only this module can build one.
#[derive(Debug)]
pub struct VerifiedActionProof {
    binding: ActionBinding,
    code_hash: String,
}

impl VerifiedActionProof {
    pub fn binding(&self) -> &ActionBinding {
        &self.binding
    }

    /// The hash of the exact code that was verified. Consuming by it is what
    /// makes a resend that raced this confirmation win.
    pub fn code_hash(&self) -> &str {
        &self.code_hash
    }
}

/// The app's storage, quotas, mail and protected action.
///
/// Every method must be atomic in storage that all replicas share, as each one
/// documents. A single SQL statement or transaction is enough. A per-process
/// mutex is not. Errors fail closed: [`request`] and [`confirm`] stop and
/// return [`ActionProofError::Backend`].
///
/// Implement one backend per protected action, or one for several that
/// dispatches on [`ActionBinding::action`].
#[async_trait::async_trait]
pub trait ActionProofBackend: Send + Sync {
    /// The app's own error, returned unchanged inside [`ActionProofError`].
    type Error: std::fmt::Debug + Send;

    /// Count one code issuance for `user_id` and `action`, and say whether it
    /// is within quota.
    ///
    /// Keyed by user and action only. Never key it by session or target, or a
    /// new session or target gets a fresh budget. Increment and compare
    /// atomically in storage all replicas share, such as with an
    /// `INSERT ... ON CONFLICT DO UPDATE ... RETURNING count` upsert. The
    /// windows and limits are up to the app; a daily cap is what bounds
    /// guessing across resends.
    ///
    /// Keep every counter until its window has ended. A cleanup that deletes
    /// counters sooner (an hourly sweep, say) resets a daily cap each time it
    /// runs.
    async fn charge_issue(&self, action: &'static str, user_id: &str) -> Result<bool, Self::Error>;

    /// Count one confirmation attempt for `user_id` and `action`, and say
    /// whether it is within quota. Same keying, atomicity and retention as
    /// [`charge_issue`](Self::charge_issue). It is charged even when no proof
    /// is pending.
    async fn charge_guess(&self, action: &'static str, user_id: &str) -> Result<bool, Self::Error>;

    /// The address to mail, read from the account now. Never take it from
    /// request input or a session copy.
    ///
    /// Return `None` unless the binding's user owns its target and the action
    /// applies to it. Nothing is stored or mailed then.
    async fn recipient(&self, binding: &ActionBinding) -> Result<Option<String>, Self::Error>;

    /// Upsert the one pending proof for (action, user_id, session_key). Set the
    /// target, recipient and code hash, reset attempts to 0, and set expiry to
    /// now plus `ttl`.
    ///
    /// Replacing the row is what invalidates the previous code on a resend.
    async fn store_pending(&self, proof: &PendingActionProof) -> Result<(), Self::Error>;

    /// Mail `code` to [`PendingActionProof::recipient`].
    ///
    /// This must be a message for this action: say what is being confirmed,
    /// that the code does not sign anyone in, and what to do if the request
    /// was not theirs. Do not reuse the login-code email. A victim whose
    /// session was taken must be able to recognise the alert.
    async fn send_code(&self, proof: &PendingActionProof, code: &str) -> Result<(), Self::Error>;

    /// Delete the pending proof for (action, user_id, session_key) only if
    /// its code hash still equals this proof's.
    ///
    /// Called when [`send_code`](Self::send_code) failed. The hash condition
    /// keeps a concurrent resend's newer code alive. Best effort: an error is
    /// logged and the row is left to expire, still bound and attempt-capped.
    async fn discard_pending(&self, proof: &PendingActionProof) -> Result<(), Self::Error>;

    /// In one atomic statement, add one to `attempts` on the pending proof
    /// that matches all of action, user_id, session_key and target, is not
    /// expired, and has `attempts < max_attempts`. Return its code hash, or
    /// `None` when no row matched.
    ///
    /// Charged before the code is even looked at, so malformed guesses count
    /// and parallel guesses cannot share one read of the counter.
    async fn charge_attempt(
        &self,
        binding: &ActionBinding,
        max_attempts: u32,
    ) -> Result<Option<String>, Self::Error>;

    /// Spend the proof and perform the protected action in one transaction.
    ///
    /// Delete the pending proof that matches all of action, user_id,
    /// session_key, target and [`VerifiedActionProof::code_hash`], is not
    /// expired, and whose recipient is still the account's current address.
    /// - Exactly one row deleted: check the action's authorization now, in
    ///   this transaction, then perform the action, commit, return `Ok(true)`.
    /// - No row: do nothing, return `Ok(false)`. The proof was already spent,
    ///   superseded by a resend, expired, or the address changed.
    /// - The authorization check or the action fails: roll back, so the proof
    ///   survives, and return `Err`.
    ///
    /// A proof only shows the user could read the account's mail just now. It
    /// grants no permission, and [`recipient`](Self::recipient)'s check at
    /// request time may be stale. Re-run every check the action would make
    /// without a proof: the target still exists, the user still owns it, a
    /// membership or role is still held. Scope the action's own statements by
    /// user and target, not by target alone.
    async fn consume_and_perform(&self, proof: &VerifiedActionProof) -> Result<bool, Self::Error>;
}

/// Why [`request`] or [`confirm`] refused.
#[derive(thiserror::Error, Debug)]
pub enum ActionProofError<E> {
    /// An account-wide issuance or guess quota is used up.
    #[error("action proof limit exceeded")]
    LimitExceeded,
    /// No usable proof. Covers none pending, expired, exhausted, a wrong or
    /// malformed code, superseded, already spent, and changed address alike.
    /// Ask for a fresh code.
    #[error("action verification required")]
    Rejected,
    /// [`ActionProofBackend::recipient`] found no owned target. Nothing was
    /// mailed.
    #[error("action target not found")]
    NotFound,
    /// [`ActionProofBackend::send_code`] failed. The code may still have
    /// reached the inbox, so this does not mean nobody received it. Its proof
    /// was discarded on a best-effort basis; if that failed too, it stays
    /// usable until it expires.
    #[error("action code delivery failed")]
    Delivery(E),
    /// The backend failed. Nothing was granted.
    #[error("action proof backend failed")]
    Backend(E),
    /// The code could not be generated, hashed or verified.
    #[error("action proof unavailable")]
    Unavailable,
}

/// Mail a fresh code for `binding`, replacing any pending one for the same
/// action, user and session.
pub async fn request<B>(
    backend: &B,
    binding: &ActionBinding,
) -> Result<(), ActionProofError<B::Error>>
where
    B: ActionProofBackend + ?Sized,
{
    use ActionProofError::{Backend, Unavailable};

    if !backend
        .charge_issue(binding.action, &binding.user_id)
        .await
        .map_err(Backend)?
    {
        return Err(ActionProofError::LimitExceeded);
    }
    let recipient = backend
        .recipient(binding)
        .await
        .map_err(Backend)?
        .ok_or(ActionProofError::NotFound)?;
    let code = crypto::generate_numeric_otp(CODE_DIGITS).map_err(|_| Unavailable)?;
    let to_hash = code.clone();
    let code_hash = tokio::task::spawn_blocking(move || crypto::hash_secret(&to_hash))
        .await
        .map_err(|_| Unavailable)?
        .map_err(|_| Unavailable)?;
    let pending = PendingActionProof {
        binding: binding.clone(),
        recipient,
        code_hash,
        ttl: CODE_TTL,
    };
    backend.store_pending(&pending).await.map_err(Backend)?;
    if let Err(e) = backend.send_code(&pending, &code).await {
        // A send error does not prove the mail went nowhere. If the discard
        // fails as well, the proof stays bound and capped until it expires.
        if let Err(discard) = backend.discard_pending(&pending).await {
            tracing::warn!(
                error = ?discard,
                action = binding.action,
                "could not discard action proof after a failed send"
            );
        }
        return Err(ActionProofError::Delivery(e));
    }
    Ok(())
}

/// Check `code` for `binding` and, if it matches, have the backend spend the
/// proof and perform the action in one transaction.
///
/// `Ok(())` means the action was performed, exactly once.
pub async fn confirm<B>(
    backend: &B,
    binding: &ActionBinding,
    code: &str,
) -> Result<(), ActionProofError<B::Error>>
where
    B: ActionProofBackend + ?Sized,
{
    use ActionProofError::{Backend, Rejected};

    if !backend
        .charge_guess(binding.action, &binding.user_id)
        .await
        .map_err(Backend)?
    {
        return Err(ActionProofError::LimitExceeded);
    }
    let code_hash = backend
        .charge_attempt(binding, MAX_ATTEMPTS)
        .await
        .map_err(Backend)?
        .ok_or(Rejected)?;
    if code.len() != CODE_DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Rejected);
    }
    let (hash, submitted) = (code_hash.clone(), code.to_owned());
    let verified = tokio::task::spawn_blocking(move || crypto::verify_secret(&hash, &submitted))
        .await
        .map_err(|_| ActionProofError::Unavailable)?;
    if !verified {
        return Err(Rejected);
    }
    let proof = VerifiedActionProof {
        binding: binding.clone(),
        code_hash,
    };
    if backend.consume_and_perform(&proof).await.map_err(Backend)? {
        Ok(())
    } else {
        Err(Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{LoggedInData, login};
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;
    use tower_sessions::{MemoryStore, Session};

    const REMOVE: &str = "passkey-removal";

    /// Lets a test stop the backend at one call, interleave other requests,
    /// then resume it.
    struct Gate {
        reached: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    }

    fn gate() -> (Gate, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached, at) = oneshot::channel();
        let (go, release) = oneshot::channel();
        (Gate { reached, release }, at, go)
    }

    async fn wait(gate: Option<Gate>) {
        if let Some(gate) = gate {
            gate.reached.send(()).unwrap();
            gate.release.await.unwrap();
        }
    }

    #[derive(Debug, PartialEq)]
    enum Fault {
        Store,
        Mail,
        NotFound,
    }

    struct Row {
        target: String,
        recipient: String,
        code_hash: String,
        attempts: u32,
        expires_at: u64,
    }

    /// Tables of a shared database. Each backend method below takes the lock
    /// once, the way one SQL statement or transaction is atomic.
    #[derive(Default)]
    struct Db {
        now: u64,
        emails: HashMap<String, String>,
        passkeys: HashSet<(String, String)>,
        proofs: HashMap<(&'static str, String, String), Row>,
        issued: HashMap<(&'static str, String), u32>,
        guessed: HashMap<(&'static str, String), u32>,
        issue_limit: u32,
        guess_limit: u32,
        counters_down: bool,
        mail_down: bool,
        mailed: Vec<(String, String, String, String)>,
        removed: Vec<String>,
    }

    /// A Postgres-shaped backend that removes a passkey.
    struct Removal {
        db: Mutex<Db>,
        mail_gate: Mutex<Option<Gate>>,
        consume_gate: Mutex<Option<Gate>>,
    }

    fn key(b: &ActionBinding) -> (&'static str, String, String) {
        (b.action, b.user_id.clone(), b.session_key.clone())
    }

    fn charge(db: &mut Db, guesses: bool, action: &'static str, user: &str) -> Result<bool, Fault> {
        if db.counters_down {
            return Err(Fault::Store);
        }
        let limit = if guesses {
            db.guess_limit
        } else {
            db.issue_limit
        };
        let table = if guesses {
            &mut db.guessed
        } else {
            &mut db.issued
        };
        let count = table.entry((action, user.to_string())).or_default();
        *count += 1;
        Ok(*count <= limit)
    }

    #[async_trait::async_trait]
    impl ActionProofBackend for Removal {
        type Error = Fault;

        async fn charge_issue(&self, action: &'static str, user: &str) -> Result<bool, Fault> {
            charge(&mut self.db.lock().unwrap(), false, action, user)
        }

        async fn charge_guess(&self, action: &'static str, user: &str) -> Result<bool, Fault> {
            charge(&mut self.db.lock().unwrap(), true, action, user)
        }

        async fn recipient(&self, b: &ActionBinding) -> Result<Option<String>, Fault> {
            let db = self.db.lock().unwrap();
            let owned = db.passkeys.contains(&(b.user_id.clone(), b.target.clone()));
            Ok(owned.then(|| db.emails[&b.user_id].clone()))
        }

        async fn store_pending(&self, p: &PendingActionProof) -> Result<(), Fault> {
            let mut db = self.db.lock().unwrap();
            let row = Row {
                target: p.binding.target.clone(),
                recipient: p.recipient.clone(),
                code_hash: p.code_hash.clone(),
                attempts: 0,
                expires_at: db.now + p.ttl.as_secs(),
            };
            db.proofs.insert(key(&p.binding), row);
            Ok(())
        }

        async fn send_code(&self, p: &PendingActionProof, code: &str) -> Result<(), Fault> {
            let held = self.mail_gate.lock().unwrap().take();
            let fail = held.is_some();
            wait(held).await;
            let mut db = self.db.lock().unwrap();
            if fail || db.mail_down {
                return Err(Fault::Mail);
            }
            let b = &p.binding;
            let mail = (
                p.recipient.clone(),
                b.action.into(),
                b.target.clone(),
                code.into(),
            );
            db.mailed.push(mail);
            Ok(())
        }

        async fn discard_pending(&self, p: &PendingActionProof) -> Result<(), Fault> {
            let mut db = self.db.lock().unwrap();
            let k = key(&p.binding);
            if db
                .proofs
                .get(&k)
                .is_some_and(|r| r.code_hash == p.code_hash)
            {
                db.proofs.remove(&k);
            }
            Ok(())
        }

        async fn charge_attempt(
            &self,
            b: &ActionBinding,
            max: u32,
        ) -> Result<Option<String>, Fault> {
            let mut db = self.db.lock().unwrap();
            let now = db.now;
            Ok(db
                .proofs
                .get_mut(&key(b))
                .filter(|r| r.target == b.target && r.expires_at > now && r.attempts < max)
                .map(|r| {
                    r.attempts += 1;
                    r.code_hash.clone()
                }))
        }

        async fn consume_and_perform(&self, p: &VerifiedActionProof) -> Result<bool, Fault> {
            let held = self.consume_gate.lock().unwrap().take();
            wait(held).await;
            let mut db = self.db.lock().unwrap();
            let b = &p.binding;
            let k = key(b);
            let spendable = db.proofs.get(&k).is_some_and(|r| {
                r.target == b.target
                    && r.code_hash == p.code_hash
                    && r.expires_at > db.now
                    && db.emails.get(&b.user_id) == Some(&r.recipient)
            });
            if !spendable {
                return Ok(false);
            }
            // The action fails: roll back, the proof stays.
            if !db.passkeys.remove(&(b.user_id.clone(), b.target.clone())) {
                return Err(Fault::NotFound);
            }
            db.proofs.remove(&k);
            db.removed.push(b.target.clone());
            Ok(true)
        }
    }

    impl Removal {
        fn new() -> Arc<Self> {
            let mut db = Db {
                issue_limit: 100,
                guess_limit: 100,
                ..Db::default()
            };
            for user in ["ada", "bob"] {
                db.emails
                    .insert(user.into(), format!("{user}@example.test"));
                db.passkeys.insert((user.into(), format!("{user}-key")));
            }
            Arc::new(Self {
                db: Mutex::new(db),
                mail_gate: Mutex::new(None),
                consume_gate: Mutex::new(None),
            })
        }

        fn db(&self) -> std::sync::MutexGuard<'_, Db> {
            self.db.lock().unwrap()
        }

        /// The code in the last mail, after checking it is the action mail
        /// sent to the account's current address.
        fn last_code(&self, b: &ActionBinding) -> String {
            let db = self.db();
            let (to, action, target, code) = db.mailed.last().unwrap();
            assert_eq!(to, &db.emails[&b.user_id]);
            assert_eq!((action.as_str(), target.as_str()), (b.action, b.target()));
            code.clone()
        }

        fn removed(&self) -> usize {
            self.db().removed.len()
        }
    }

    async fn browser(user: &str) -> Session {
        let session = Session::new(None, Arc::new(MemoryStore::default()), None);
        let data = LoggedInData {
            id: user.into(),
            sub: format!("sub-{user}"),
            email: format!("{user}@example.test"),
            username: user.into(),
            avatar_url: None,
            id_token: String::new(),
        };
        login(&session, &data).await.unwrap();
        session.save().await.unwrap();
        session
    }

    async fn bind(session: &Session, target: &str) -> ActionBinding {
        ActionBinding::from_session(session, REMOVE, target)
            .await
            .unwrap()
    }

    /// Request a code for `b` and return it from the captured mail.
    async fn issue(backend: &Removal, b: &ActionBinding) -> String {
        request(backend, b).await.unwrap();
        backend.last_code(b)
    }

    fn wrong(code: &str) -> &'static str {
        if code == "000000" { "111111" } else { "000000" }
    }

    #[tokio::test]
    async fn binding_needs_a_login_and_follows_the_session_id() {
        let anonymous = Session::new(None, Arc::new(MemoryStore::default()), None);
        assert!(matches!(
            ActionBinding::from_session(&anonymous, REMOVE, "ada-key").await,
            Err(AuthError::UserNotLoggedIn)
        ));
        let session = browser("ada").await;
        let b = bind(&session, "ada-key").await;
        assert_eq!(b.user_id(), "ada");
        assert_ne!(b.session_key(), session.id().unwrap().to_string());
        session.cycle_id().await.unwrap();
        session.save().await.unwrap();
        assert_ne!(
            b.session_key(),
            bind(&session, "ada-key").await.session_key()
        );
    }

    #[tokio::test]
    async fn a_mailed_code_performs_the_action_once() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "ada-key").await;
        assert!(matches!(
            confirm(&*backend, &b, "123456").await,
            Err(ActionProofError::Rejected)
        ));
        let code = issue(&backend, &b).await;
        let stored = backend.db().proofs[&key(&b)].code_hash.clone();
        assert!(stored.starts_with("$argon2id$"));
        assert_ne!(stored, code);
        confirm(&*backend, &b, &code).await.unwrap();
        assert_eq!(backend.db().removed, vec!["ada-key".to_string()]);
        assert!(matches!(
            confirm(&*backend, &b, &code).await,
            Err(ActionProofError::Rejected)
        ));
        assert_eq!(backend.removed(), 1);
    }

    #[tokio::test]
    async fn a_code_is_bound_to_action_user_session_and_target() {
        let backend = Removal::new();
        let ada = browser("ada").await;
        let b = bind(&ada, "ada-key").await;
        let code = issue(&backend, &b).await;
        let other_session = bind(&browser("ada").await, "ada-key").await;
        let other_user = bind(&browser("bob").await, "bob-key").await;
        let other_target = bind(&ada, "bob-key").await;
        let other_action = ActionBinding::from_session(&ada, "account-deletion", "ada-key")
            .await
            .unwrap();
        for stranger in [other_session, other_user, other_target, other_action] {
            assert!(matches!(
                confirm(&*backend, &stranger, &code).await,
                Err(ActionProofError::Rejected)
            ));
        }
        assert_eq!(backend.removed(), 0);
        confirm(&*backend, &b, &code).await.unwrap();
    }

    #[tokio::test]
    async fn parallel_wrong_and_malformed_guesses_spend_exactly_five_attempts() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "ada-key").await;
        let code = issue(&backend, &b).await;
        let guesses = [
            "",
            "12345",
            "abcdef",
            "1234567",
            wrong(&code),
            wrong(&code),
            "x",
            "",
        ];
        let tasks: Vec<_> = guesses
            .into_iter()
            .map(|guess| {
                let (backend, b) = (backend.clone(), b.clone());
                tokio::spawn(async move { confirm(&*backend, &b, guess).await })
            })
            .collect();
        for task in tasks {
            assert!(matches!(
                task.await.unwrap(),
                Err(ActionProofError::Rejected)
            ));
        }
        assert_eq!(backend.db().proofs[&key(&b)].attempts, MAX_ATTEMPTS);
        assert!(matches!(
            confirm(&*backend, &b, &code).await,
            Err(ActionProofError::Rejected)
        ));
        assert_eq!(backend.removed(), 0);
    }

    #[tokio::test]
    async fn expired_or_readdressed_codes_are_rejected() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "ada-key").await;
        let code = issue(&backend, &b).await;
        backend.db().now += CODE_TTL.as_secs();
        assert!(matches!(
            confirm(&*backend, &b, &code).await,
            Err(ActionProofError::Rejected)
        ));
        let code = issue(&backend, &b).await;
        backend
            .db()
            .emails
            .insert("ada".into(), "new@example.test".into());
        assert!(matches!(
            confirm(&*backend, &b, &code).await,
            Err(ActionProofError::Rejected)
        ));
        assert_eq!(backend.removed(), 0);
    }

    #[tokio::test]
    async fn parallel_valid_confirms_perform_once() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "ada-key").await;
        let code = issue(&backend, &b).await;
        let (first, second) =
            tokio::join!(confirm(&*backend, &b, &code), confirm(&*backend, &b, &code));
        assert_ne!(first.is_ok(), second.is_ok());
        assert_eq!(backend.removed(), 1);
    }

    #[tokio::test]
    async fn a_resend_beats_a_confirm_already_verified() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "ada-key").await;
        let old = issue(&backend, &b).await;
        let (held, at_consume, resume) = gate();
        *backend.consume_gate.lock().unwrap() = Some(held);
        let confirming = {
            let (backend, b, old) = (backend.clone(), b.clone(), old.clone());
            tokio::spawn(async move { confirm(&*backend, &b, &old).await })
        };
        at_consume.await.unwrap();
        let new = issue(&backend, &b).await;
        resume.send(()).unwrap();
        assert!(matches!(
            confirming.await.unwrap(),
            Err(ActionProofError::Rejected)
        ));
        assert_eq!(backend.removed(), 0);
        confirm(&*backend, &b, &new).await.unwrap();
    }

    #[tokio::test]
    async fn failed_delivery_discards_only_its_own_code() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "ada-key").await;
        backend.db().mail_down = true;
        assert!(matches!(
            request(&*backend, &b).await,
            Err(ActionProofError::Delivery(Fault::Mail))
        ));
        assert!(backend.db().proofs.is_empty());
        backend.db().mail_down = false;

        // The first send stalls and then fails, after a resend has delivered.
        let (held, at_send, resume) = gate();
        *backend.mail_gate.lock().unwrap() = Some(held);
        let stalled = {
            let (backend, b) = (backend.clone(), b.clone());
            tokio::spawn(async move { request(&*backend, &b).await })
        };
        at_send.await.unwrap();
        let code = issue(&backend, &b).await;
        resume.send(()).unwrap();
        assert!(matches!(
            stalled.await.unwrap(),
            Err(ActionProofError::Delivery(Fault::Mail))
        ));
        confirm(&*backend, &b, &code).await.unwrap();
    }

    #[tokio::test]
    async fn foreign_targets_mail_nothing() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "bob-key").await;
        assert!(matches!(
            request(&*backend, &b).await,
            Err(ActionProofError::NotFound)
        ));
        assert!(backend.db().mailed.is_empty() && backend.db().proofs.is_empty());
    }

    #[tokio::test]
    async fn issuance_limit_spans_sessions_and_keeps_a_delivered_code() {
        let backend = Removal::new();
        backend.db().issue_limit = 2;
        let a = bind(&browser("ada").await, "ada-key").await;
        let b = bind(&browser("ada").await, "ada-key").await;
        issue(&backend, &a).await;
        let code = issue(&backend, &b).await;
        for session in [&a, &b] {
            assert!(matches!(
                request(&*backend, session).await,
                Err(ActionProofError::LimitExceeded)
            ));
        }
        assert_eq!(backend.db().mailed.len(), 2);
        confirm(&*backend, &b, &code).await.unwrap();
    }

    #[tokio::test]
    async fn guess_limit_spans_resends_and_sessions() {
        let backend = Removal::new();
        backend.db().guess_limit = 3;
        let a = bind(&browser("ada").await, "ada-key").await;
        let b = bind(&browser("ada").await, "ada-key").await;
        let code = issue(&backend, &a).await;
        let _ = confirm(&*backend, &a, wrong(&code)).await;
        let code = issue(&backend, &a).await;
        let _ = confirm(&*backend, &a, wrong(&code)).await;
        let _ = confirm(&*backend, &b, "000000").await;
        assert!(matches!(
            confirm(&*backend, &a, &code).await,
            Err(ActionProofError::LimitExceeded)
        ));
        assert_eq!(backend.removed(), 0);
    }

    #[tokio::test]
    async fn unavailable_quotas_fail_closed() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "ada-key").await;
        let code = issue(&backend, &b).await;
        backend.db().counters_down = true;
        assert!(matches!(
            request(&*backend, &b).await,
            Err(ActionProofError::Backend(Fault::Store))
        ));
        assert!(matches!(
            confirm(&*backend, &b, &code).await,
            Err(ActionProofError::Backend(Fault::Store))
        ));
        assert_eq!(backend.db().mailed.len(), 1);
        assert_eq!(backend.removed(), 0);
    }

    #[tokio::test]
    async fn a_failed_action_keeps_the_proof() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "ada-key").await;
        let code = issue(&backend, &b).await;
        backend.db().passkeys.clear();
        assert!(matches!(
            confirm(&*backend, &b, &code).await,
            Err(ActionProofError::Backend(Fault::NotFound))
        ));
        assert!(backend.db().proofs.contains_key(&key(&b)));
    }

    #[tokio::test]
    async fn a_proof_does_not_outlive_ownership() {
        let backend = Removal::new();
        let b = bind(&browser("ada").await, "ada-key").await;
        let code = issue(&backend, &b).await;
        // The passkey changes hands between request and confirm.
        {
            let mut db = backend.db();
            db.passkeys.remove(&("ada".into(), "ada-key".into()));
            db.passkeys.insert(("bob".into(), "ada-key".into()));
        }
        assert!(matches!(
            confirm(&*backend, &b, &code).await,
            Err(ActionProofError::Backend(Fault::NotFound))
        ));
        assert!(
            backend
                .db()
                .passkeys
                .contains(&("bob".into(), "ada-key".into()))
        );
        assert_eq!(backend.removed(), 0);
    }
}
