//! The login page for the self-owned flow, as a Topcoat component.
//!
//! The server renders every step; `local_login.js` (inlined) drives the flow
//! against `local_auth_router`, the same way the Dioxus `LocalLoginPage` does.
//! Same Tailwind + DaisyUI classes and host-stylesheet hooks as that page.

use ::topcoat::{
    Result,
    context::Cx,
    router::request,
    view::{NodeViewParts, PartsWriter, View, component, view},
};

use crate::locale::{Locale, tr_in};

const SCRIPT: &str = include_str!("local_login.js");
const DE_CATALOG: &str = include_str!("../../locales/de.json");

/// Multi-step login page for the self-owned flow (`local_auth_router`): email
/// OTP with auto-passkey detection, passkey autofill, an optional password
/// step, terms acceptance, and a one-time passkey enrollment offer.
///
/// Render it inside a full HTML document. The locale is negotiated from the
/// request (`oxidt_locale` cookie, then `Accept-Language`). `captcha` is the
/// bollwark `(server_url, site_key)`, as in the Dioxus page.
#[component]
pub async fn local_login_page(
    cx: &Cx,
    redirect_url: &str,
    #[default] captcha: Option<(String, String)>,
    #[default] app_name: Option<String>,
    #[default] logo_src: Option<String>,
) -> Result<impl View> {
    let locale = Locale::from_headers(request::headers(cx));
    let t = move |text: &str| tr_in(locale, text);
    let heading = match &app_name {
        Some(name) => t("Welcome to {name}").replace("{name}", name),
        None => t("Sign in"),
    };
    let catalog = match locale {
        Locale::De => DE_CATALOG,
        Locale::En => "{}",
    };

    Ok(view! {
        <div
            id="oxidt-login"
            class="auth-bg min-h-screen flex flex-col items-center justify-center bg-base-200 p-4"
            data-redirect=(redirect_url)
            data-captcha=(if captcha.is_some() { "1" } else { "0" })
        >
            <div class="auth-card card w-full max-w-md bg-base-100 animate-scale-in">
                <div class="card-body p-7 sm:p-9">
                    <div class="text-center mb-7">
                        if let Some(src) = &logo_src {
                            <img src=(src) alt=(app_name.as_deref().unwrap_or_default()) class="h-16 mx-auto mb-4">
                        }
                        <h1 class="text-2xl font-bold tracking-tight">(heading)</h1>
                        <p class="text-sm text-base-content/60 mt-1.5">(t("Sign in or create an account"))</p>
                    </div>

                    // Enabled by the script, so a submit before it ran can't
                    // fall through to a native GET. `contents` keeps it out of
                    // the layout.
                    <fieldset class="contents" disabled=(true)>
                        <div data-alert="success" hidden=(true) class="animate-alert-in flex items-start gap-2.5 rounded-xl border border-success/25 bg-success/10 px-4 py-3 text-sm text-success mb-4">
                            icon(d: CHECK_CIRCLE, class: "stroke-current shrink-0 h-5 w-5 mt-px", stroke_width: "2")
                            <span data-msg=""></span>
                        </div>
                        <div data-alert="error" hidden=(true) class="animate-alert-in flex items-start gap-2.5 rounded-xl border border-error/25 bg-error/10 px-4 py-3 text-sm text-error mb-4">
                            icon(d: X_CIRCLE, class: "stroke-current shrink-0 h-5 w-5 mt-px", stroke_width: "2")
                            <span data-msg=""></span>
                        </div>

                        <div data-step="email" class="animate-step-in">
                            <form data-form="email" novalidate=(true) class="space-y-4">
                                <fieldset class="fieldset">
                                    <label class="fieldset-label" for="oxidt-login-email">(t("Email address"))</label>
                                    <input
                                        id="oxidt-login-email"
                                        name="email"
                                        type="email"
                                        class="input input-bordered w-full"
                                        placeholder="you@example.com"
                                        required=(true)
                                        autofocus=(true)
                                        autocomplete="username webauthn"
                                        inputmode="email"
                                        autocapitalize="none"
                                        spellcheck="false"
                                    >
                                    <p data-email-error="" hidden=(true) class="text-xs text-error mt-1.5 animate-alert-in"></p>
                                </fieldset>
                                if let Some((server_url, site_key)) = &captcha {
                                    <script src=(format!("{server_url}/v1/widget.js")) defer=(true)></script>
                                    <div
                                        id="bollwark-container"
                                        class="flex justify-center"
                                        data-sitekey=(site_key)
                                        data-server-url=(server_url)
                                        data-mode="invisible"
                                    ></div>
                                }
                                <button type="submit" class="btn btn-primary w-full transition-transform duration-150 hover:-translate-y-0.5 active:translate-y-0">
                                    spinner()
                                    (t("Continue"))
                                </button>
                                <div data-webauthn="" hidden=(true)>
                                    <div class="divider text-xs text-base-content/40 my-1">(t("or"))</div>
                                    <button type="button" data-action="passkey" class="btn btn-outline w-full gap-2 transition-transform duration-150 hover:-translate-y-0.5 active:translate-y-0">
                                        icon(d: FINGERPRINT, class: "h-5 w-5", stroke_width: "1.5")
                                        (t("Sign in with a passkey"))
                                    </button>
                                </div>
                                <p class="text-xs text-base-content/40 text-center mt-3">
                                    (t("No account yet? We'll create one for you."))
                                </p>
                            </form>
                        </div>

                        <div data-step="passkey" hidden=(true) class="animate-step-in text-center space-y-4 py-4">
                            <div class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-primary/10 text-primary animate-pulse-glow">
                                icon(d: FINGERPRINT, class: "h-8 w-8", stroke_width: "1.5")
                            </div>
                            <p class="font-medium">(t("Waiting for authentication..."))</p>
                            <p class="text-sm text-base-content/50">(t("Follow the prompt from your browser or device."))</p>
                            <div class="flex justify-center gap-2 mt-4">
                                <button type="button" data-action="passkey-back" class="btn btn-ghost btn-sm">(t("Back"))</button>
                                <button type="button" data-action="use-code" class="btn btn-ghost btn-sm">(t("Use email code instead"))</button>
                            </div>
                        </div>

                        <div data-step="passkey-retry" hidden=(true) class="animate-step-in text-center space-y-4 py-4">
                            <div class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-base-content/5 text-base-content/50">
                                icon(d: FINGERPRINT, class: "h-8 w-8", stroke_width: "1.5")
                            </div>
                            <p class="font-medium">(t("Passkey sign-in didn't work"))</p>
                            <p class="text-sm text-base-content/50">(t("You can try again or use another way to sign in."))</p>
                            <div class="flex flex-col gap-2">
                                <button type="button" data-action="retry" class="btn btn-primary">(t("Try again"))</button>
                                <button type="button" data-action="use-code" class="btn btn-ghost btn-sm">(t("Use email code instead"))</button>
                                <button type="button" data-action="passkey-back" class="btn btn-ghost btn-sm">(t("Back"))</button>
                            </div>
                        </div>

                        <div data-step="offer" hidden=(true) class="animate-step-in text-center space-y-4 py-4">
                            <div class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-primary/10 text-primary">
                                icon(d: FINGERPRINT, class: "h-8 w-8", stroke_width: "1.5")
                            </div>
                            <p class="font-medium">(t("Skip the email code next time"))</p>
                            <p class="text-sm text-base-content/50">(t("Add a passkey to sign in with your fingerprint, face, or screen lock."))</p>
                            <div class="flex flex-col gap-2">
                                <button type="button" data-action="offer-add" class="btn btn-primary">
                                    spinner()
                                    (t("Add passkey"))
                                </button>
                                <button type="button" data-action="offer-skip" class="btn btn-ghost btn-sm">(t("Not now"))</button>
                            </div>
                        </div>

                        <div data-step="tos" hidden=(true) class="animate-step-in space-y-4">
                            <div class="text-center">
                                <h2 class="text-lg font-semibold">(t("Almost there!"))</h2>
                                <p class="text-sm text-base-content/70 mt-1">(t("Please review and accept our terms to continue."))</p>
                            </div>
                            <label class="label cursor-pointer justify-start gap-3">
                                <input type="checkbox" data-tos-check="" class="checkbox checkbox-primary">
                                <span class="label-text">
                                    (t("I agree to the "))
                                    <a href="/legal/terms" target="_blank" class="link link-primary">(t("Terms of Service"))</a>
                                    (t(" and "))
                                    <a href="/legal/privacy" target="_blank" class="link link-primary">(t("Privacy Policy"))</a>
                                </span>
                            </label>
                            <button type="button" data-action="tos-accept" class="btn btn-primary w-full">
                                spinner()
                                (t("Continue"))
                            </button>
                        </div>

                        <div data-step="password" hidden=(true) class="animate-step-in space-y-4">
                            <div class="text-center">
                                <p class="text-sm text-base-content/70">(t("Enter the password for"))</p>
                                <p class="font-medium text-sm" data-email=""></p>
                            </div>
                            <form data-form="password" class="space-y-4">
                                <fieldset class="fieldset">
                                    <label class="fieldset-label" for="oxidt-login-password">(t("Password"))</label>
                                    <input
                                        id="oxidt-login-password"
                                        name="password"
                                        type="password"
                                        class="input input-bordered w-full"
                                        placeholder="••••••••"
                                        autofocus=(true)
                                        autocomplete="current-password"
                                    >
                                </fieldset>
                                <button type="submit" class="btn btn-primary w-full">
                                    spinner()
                                    (t("Sign in"))
                                </button>
                            </form>
                            <div class="flex justify-between items-center text-sm">
                                <button type="button" data-action="back" class="btn btn-ghost btn-sm text-base-content/50">(t("Back"))</button>
                                <button type="button" data-action="use-code" data-otp-only="" class="btn btn-ghost btn-sm text-primary">(t("Email me a code instead"))</button>
                            </div>
                        </div>

                        <div data-step="otp" hidden=(true) class="animate-step-in space-y-4">
                            <div class="text-center">
                                <div data-new-user="" hidden=(true) class="badge badge-success badge-outline mb-2">(t("Account created"))</div>
                                <p class="text-sm text-base-content/70">(t("We sent a verification code to"))</p>
                                <p class="font-medium text-sm" data-email=""></p>
                            </div>
                            <form data-form="otp" class="space-y-4">
                                <fieldset class="fieldset">
                                    <label class="fieldset-label" for="oxidt-login-otp">(t("Verification code"))</label>
                                    <input
                                        id="oxidt-login-otp"
                                        name="otp"
                                        type="text"
                                        class="input input-bordered w-full text-center text-xl tracking-widest"
                                        placeholder="000000"
                                        maxlength="8"
                                        autofocus=(true)
                                        autocomplete="one-time-code"
                                        inputmode="numeric"
                                    >
                                </fieldset>
                                <button type="submit" class="btn btn-primary w-full">
                                    spinner()
                                    (t("Verify"))
                                </button>
                            </form>
                            <div class="flex justify-between items-center text-sm">
                                <button type="button" data-action="back" class="btn btn-ghost btn-sm text-base-content/50">(t("Back"))</button>
                                <button type="button" data-action="resend" class="btn btn-ghost btn-sm text-primary">(t("Resend code"))</button>
                            </div>
                        </div>

                        <div data-step="verifying" hidden=(true) class="animate-step-in text-center space-y-4 py-4">
                            <span class="loading loading-spinner loading-lg text-primary"></span>
                            <p class="text-base-content/70">(t("Verifying..."))</p>
                        </div>

                        <div data-step="success" hidden=(true) class="animate-step-in text-center space-y-4 py-4">
                            <div class="text-success text-4xl mb-2">
                                icon(d: CHECK_CIRCLE, class: "h-12 w-12 mx-auto", stroke_width: "2")
                            </div>
                            <p class="font-medium">(t("Login successful!"))</p>
                            <p class="text-sm text-base-content/50">(t("Redirecting..."))</p>
                            <span class="loading loading-spinner loading-sm"></span>
                        </div>
                    </fieldset>

                    <div class="mt-6 flex items-center justify-center gap-1.5 text-xs text-base-content/40">
                        icon(d: LOCK, class: "h-3.5 w-3.5", stroke_width: "1.5")
                        <span>(t("Secured with passkeys & encryption"))</span>
                    </div>
                </div>
            </div>
            <script id="oxidt-login-i18n" type="application/json">(Trusted(catalog))</script>
            <script>(Trusted(SCRIPT))</script>
        </div>
    })
}

/// Markup written verbatim. Only for compile-time constants of this crate:
/// the script and the locale catalog, neither of which contains `</`.
struct Trusted(&'static str);

impl NodeViewParts for Trusted {
    fn into_view_parts(self, _cx: &Cx, parts: &mut PartsWriter<'_>) {
        parts.push_static_str_unescaped(self.0);
    }
}

#[component]
async fn spinner() -> Result<impl View> {
    Ok(
        view! { <span data-spinner="" hidden=(true) class="loading loading-spinner loading-sm"></span> },
    )
}

const FINGERPRINT: &str = "M7.864 4.243A7.5 7.5 0 0119.5 10.5c0 2.92-.556 5.709-1.568 8.268M5.742 6.364A7.465 7.465 0 004.5 10.5a7.464 7.464 0 01-1.15 3.993m1.989 3.559A11.209 11.209 0 008.25 10.5a3.75 3.75 0 117.5 0c0 .527-.021 1.049-.064 1.565M12 10.5a14.94 14.94 0 01-3.6 9.75m6.633-4.596a18.666 18.666 0 01-2.485 5.33";
const LOCK: &str = "M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z";
const CHECK_CIRCLE: &str = "M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z";
const X_CIRCLE: &str = "M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z";

/// Inline outline icon (kept local to avoid an icon-crate dep in the auth crate).
#[component]
async fn icon(
    d: &'static str,
    class: &'static str,
    stroke_width: &'static str,
) -> Result<impl View> {
    Ok(view! {
        <svg xmlns="http://www.w3.org/2000/svg" class=(class) fill="none" viewBox="0 0 24 24" stroke-width=(stroke_width) stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d=(d)></path>
        </svg>
    })
}
