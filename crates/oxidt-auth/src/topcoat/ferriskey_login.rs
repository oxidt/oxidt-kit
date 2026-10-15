//! The FerrisKey login page, as a Topcoat component.
//!
//! The server renders every step; `ferriskey_login.js` (inlined) drives the
//! flow against `auth_router`, the same way the Dioxus `LoginPage` does. Same
//! Tailwind + DaisyUI classes as that page.

use ::topcoat::{
    Result,
    context::Cx,
    router::request,
    view::{View, class, component, view},
};

use super::parts::{CHECK_CIRCLE, Trusted, X_CIRCLE, catalog, icon, spinner};
use crate::handlers::is_safe_redirect_url;
use crate::locale::{Locale, tr_in};

const SCRIPT: &str = include_str!("ferriskey_login.js");

/// Multi-step login page for the FerrisKey flow (`auth_router`): email in,
/// then a passkey, password or emailed code as the server decides; captcha-
/// gated registration, terms acceptance, and the dev login in debug builds
/// with `DEV_LOGIN=true`.
///
/// Render it inside a full HTML document. `redirect_url` is where to go after
/// login; anything but a relative path is dropped, so the server's default
/// applies. `embed` leaves out the full-page wrapper, card and heading, for a
/// host that frames the form itself. The locale is negotiated from the request
/// (`oxidt_locale` cookie, then `Accept-Language`). `captcha` is the bollwark
/// `(server_url, site_key)`, as in the Dioxus page.
#[component]
pub async fn ferriskey_login_page(
    cx: &Cx,
    redirect_url: &str,
    #[default] embed: bool,
    #[default] captcha: Option<(String, String)>,
) -> Result<impl View> {
    let locale = Locale::from_headers(request::headers(cx));
    let t = move |text: &str| tr_in(locale, text);
    let start = if redirect_url.contains("accept_tos=true") {
        "tos"
    } else {
        "email"
    };
    let redirect_url = if is_safe_redirect_url(redirect_url) {
        redirect_url
    } else {
        ""
    };

    Ok(view! {
        <div
            id="oxidt-login"
            class=(class!(
                "min-h-screen flex flex-col items-center justify-center bg-base-200" if !embed,
            ))
            data-redirect=(redirect_url)
            data-captcha=(if captcha.is_some() { "1" } else { "0" })
            data-start=(start)
        >
            if embed {
                steps(redirect_url: redirect_url, captcha: captcha)
            } else {
                <div class="card w-full max-w-md bg-base-100 shadow-xl">
                    <div class="card-body">
                        <div class="text-center mb-6">
                            <h1 class="text-2xl font-bold">(t("Welcome"))</h1>
                            <p class="text-sm text-base-content/60 mt-1">
                                (t("Sign in or create an account"))
                            </p>
                        </div>
                        steps(redirect_url: redirect_url, captcha: captcha)
                    </div>
                </div>
            }
            <script id="oxidt-login-i18n" type="application/json">
                (Trusted(catalog(locale)))
            </script>
            <script>(Trusted(SCRIPT))</script>
        </div>
    })
}

/// Every step of the flow, plus the dev login below it.
#[component]
async fn steps(
    cx: &Cx,
    redirect_url: &str,
    captcha: Option<(String, String)>,
) -> Result<impl View> {
    let locale = Locale::from_headers(request::headers(cx));
    let t = move |text: &str| tr_in(locale, text);
    // The same two gates as `POST /auth/dev-login`: a debug build, and
    // `DEV_LOGIN=true`. Release builds have neither the route nor this control.
    let dev_login = cfg!(debug_assertions) && std::env::var("DEV_LOGIN").as_deref() == Ok("true");

    Ok(view! {
        // Enabled by the script, so a submit before it ran can't fall through
        // to a native GET. `contents` keeps it out of the layout.
        <fieldset data-steps="" class="contents" disabled=(true)>
            <div data-alert="success" hidden=(true) class="alert alert-success mb-4">
                icon(
                    d: CHECK_CIRCLE,
                    class: "stroke-current shrink-0 h-5 w-5",
                    stroke_width: "2"
                )
                <span data-msg=""></span>
            </div>
            <div data-alert="error" hidden=(true) class="alert alert-error mb-4">
                icon(
                    d: X_CIRCLE,
                    class: "stroke-current shrink-0 h-5 w-5",
                    stroke_width: "2"
                )
                <span data-msg=""></span>
            </div>

            <div data-step="email">
                <form data-form="email" class="space-y-4">
                    <fieldset class="fieldset">
                        <label class="fieldset-label" for="oxidt-login-email">
                            (t("Email address"))
                        </label>
                        <input
                            id="oxidt-login-email"
                            name="email"
                            type="email"
                            class="input input-bordered w-full"
                            placeholder="you@example.com"
                            autocomplete="email"
                            inputmode="email"
                            autocapitalize="none"
                            spellcheck="false"
                            required=(true)
                            autofocus=(true)
                        >
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
                    <button type="submit" class="btn btn-primary w-full">
                        spinner()
                        (t("Continue"))
                    </button>
                    <p class="text-xs text-base-content/40 text-center mt-3">
                        (t("No account yet? We'll create one for you."))
                    </p>
                </form>
            </div>

            <div data-step="detecting" hidden=(true) class="text-center space-y-4 py-4">
                <span class="loading loading-spinner loading-lg text-primary"></span>
                <p class="text-base-content/70">(t("Setting things up..."))</p>
            </div>

            <div data-step="passkey" hidden=(true) class="text-center space-y-4 py-4">
                <span class="loading loading-spinner loading-lg text-primary"></span>
                <p class="font-medium">(t("Waiting for authentication..."))</p>
                <p class="text-sm text-base-content/50">
                    (t("Follow the prompt from your browser or device."))
                </p>
                <button
                    type="button"
                    data-action="back"
                    class="btn btn-ghost btn-sm text-base-content/50"
                >
                    (t("Back"))
                </button>
            </div>

            <div data-step="password" hidden=(true) class="space-y-4">
                <div class="text-center">
                    <p class="text-sm text-base-content/70">
                        (t("Enter your password for"))
                    </p>
                    <p class="font-medium text-sm" data-email=""></p>
                </div>
                <form data-form="password" class="space-y-4">
                    <fieldset class="fieldset">
                        <label class="fieldset-label" for="oxidt-login-password">
                            (t("Password"))
                        </label>
                        <input
                            id="oxidt-login-password"
                            name="password"
                            type="password"
                            class="input input-bordered w-full"
                            placeholder=(t("Enter your password"))
                            autofocus=(true)
                            autocomplete="current-password"
                        >
                    </fieldset>
                    <button type="submit" class="btn btn-primary w-full">
                        spinner()
                        (t("Sign in"))
                    </button>
                </form>
                <div class="flex justify-start items-center text-sm">
                    <button
                        type="button"
                        data-action="back"
                        class="btn btn-ghost btn-sm text-base-content/50"
                    >
                        (t("Back"))
                    </button>
                </div>
            </div>

            <div data-step="otp" hidden=(true) class="space-y-4">
                <div class="text-center">
                    <div
                        data-new-user=""
                        hidden=(true)
                        class="badge badge-success badge-outline mb-2"
                    >
                        (t("Account created"))
                    </div>
                    <p class="text-sm text-base-content/70">
                        (t("We sent a verification code to"))
                    </p>
                    <p class="font-medium text-sm" data-email=""></p>
                </div>
                <form data-form="otp" class="space-y-4">
                    <fieldset class="fieldset">
                        <label class="fieldset-label" for="oxidt-login-otp">
                            (t("Verification code"))
                        </label>
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
                    <button
                        type="button"
                        data-action="back"
                        class="btn btn-ghost btn-sm text-base-content/50"
                    >
                        (t("Back"))
                    </button>
                    <div class="flex gap-1">
                        <button
                            type="button"
                            data-action="use-password"
                            hidden=(true)
                            class="btn btn-ghost btn-sm text-primary"
                        >
                            (t("Use password"))
                        </button>
                        <button
                            type="button"
                            data-action="resend"
                            class="btn btn-ghost btn-sm text-primary"
                        >
                            (t("Resend code"))
                        </button>
                    </div>
                </div>
            </div>

            <div data-step="tos" hidden=(true) class="space-y-4">
                <div class="text-center">
                    <h2 class="text-lg font-semibold">(t("Almost there!"))</h2>
                    <p class="text-sm text-base-content/70 mt-1">
                        (t("Please review and accept our terms to continue."))
                    </p>
                </div>
                <label class="label cursor-pointer justify-start gap-3">
                    <input
                        type="checkbox"
                        data-tos-check=""
                        class="checkbox checkbox-primary"
                    >
                    <span class="label-text">
                        (t("I agree to the "))
                        <a
                            href="/legal/terms"
                            target="_blank"
                            class="link link-primary"
                        >
                            (t("Terms of Service"))
                        </a>
                        (t(" and "))
                        <a
                            href="/legal/privacy"
                            target="_blank"
                            class="link link-primary"
                        >
                            (t("Privacy Policy"))
                        </a>
                    </span>
                </label>
                <button
                    type="button"
                    data-action="tos-accept"
                    class="btn btn-primary w-full"
                >
                    spinner()
                    (t("Continue"))
                </button>
            </div>

            <div data-step="verifying" hidden=(true) class="text-center space-y-4 py-4">
                <span class="loading loading-spinner loading-lg text-primary"></span>
                <p class="text-base-content/70">(t("Verifying..."))</p>
            </div>

            <div data-step="success" hidden=(true) class="text-center space-y-4 py-4">
                <div class="text-success text-4xl mb-2">
                    icon(d: CHECK_CIRCLE, class: "h-12 w-12 mx-auto", stroke_width: "2")
                </div>
                <p class="font-medium">(t("Login successful!"))</p>
                <p class="text-sm text-base-content/50">(t("Redirecting..."))</p>
                <span class="loading loading-spinner loading-sm"></span>
            </div>
        </fieldset>

        if dev_login {
            <div class="divider text-xs text-base-content/40">"Local development"</div>
            // A plain form POST: it works before the script runs, and the
            // browser sends the Origin the CSRF middleware checks.
            <form method="post" action="/auth/dev-login">
                <input type="hidden" name="redirect_url" value=(redirect_url)>
                <button type="submit" class="btn btn-outline btn-warning btn-sm w-full">
                    "Dev login (local only)"
                </button>
            </form>
            <p class="mt-2 text-center text-xs text-base-content/40">
                "Signs in as dev@localhost without an identity provider."
            </p>
        }
    })
}
