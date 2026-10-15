// Drives the Topcoat `ferriskey_login_page`. A port of the Dioxus `LoginPage`
// (login_page.rs): same endpoints, same steps.
(() => {
  const root = document.getElementById("oxidt-login");
  if (!root) return;
  const $ = (sel) => root.querySelector(sel);
  const $$ = (sel) => root.querySelectorAll(sel);

  let catalog = {};
  try {
    catalog = JSON.parse(document.getElementById("oxidt-login-i18n").textContent);
  } catch (_) {}
  const tr = (text) => catalog[text] || text;

  const redirectUrl = root.dataset.redirect || "";
  const hasCaptcha = root.dataset.captcha === "1";
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const isCancel = (msg) => msg.includes("cancelled") || msg.includes("timed out");

  let loading = false;
  let passkeyOptions = null;
  // Bumped by every ceremony start and by "Back", so a late-resolving
  // ceremony can't act on a flow the user has left.
  let attempt = 0;
  // Abort handle of the WebAuthn get() in flight.
  let ceremony = null;

  // ── UI state ──────────────────────────────────────────────────────

  function show(name) {
    $$("[data-step]").forEach((el) => (el.hidden = el.dataset.step !== name));
    const focus = $(`[data-step="${name}"] [autofocus]`);
    if (focus) focus.focus();
    if (name === "email") mountCaptcha();
  }

  function setLoading(on) {
    loading = on;
    $$("[data-steps] button").forEach((b) => (b.disabled = on));
    $$("[data-spinner]").forEach((s) => (s.hidden = !on));
    updateTerms();
  }

  function updateTerms() {
    $('[data-action="tos-accept"]').disabled = loading || !$("[data-tos-check]").checked;
  }

  function alertBox(kind, msg) {
    const el = $(`[data-alert="${kind}"]`);
    el.hidden = !msg;
    if (msg) el.querySelector("[data-msg]").textContent = tr(msg);
  }
  const showError = (msg) => alertBox("error", msg);
  const showSuccess = (msg) => alertBox("success", msg);
  const clearAlerts = () => {
    showError(null);
    showSuccess(null);
  };

  // ── HTTP ──────────────────────────────────────────────────────────

  async function postJson(url, body) {
    let resp;
    try {
      resp = await fetch(url, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (_) {
      throw new Error("Network error");
    }
    if (!resp.ok) {
      throw new Error((await resp.text().catch(() => "")) || "Request failed");
    }
    try {
      return await resp.json();
    } catch (_) {
      throw new Error("Failed to parse JSON");
    }
  }

  // ── WebAuthn ──────────────────────────────────────────────────────

  function b64urlToBuffer(s) {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  }

  function bufferToB64url(buf) {
    let bin = "";
    new Uint8Array(buf).forEach((b) => (bin += String.fromCharCode(b)));
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  // FerrisKey returns the unwrapped W3C request options; tolerate a
  // `publicKey` wrapper for forward compat.
  async function getPasskey(raw) {
    if (!navigator.credentials || !navigator.credentials.get) {
      throw new Error("Passkeys are not supported in this browser or context.");
    }
    const options = { ...(raw.publicKey || raw) };
    if (options.challenge) options.challenge = b64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((c) => ({
        ...c,
        id: b64urlToBuffer(c.id),
      }));
    }
    const controller = new AbortController();
    ceremony = controller;
    let c;
    try {
      c = await navigator.credentials.get({ publicKey: options, signal: controller.signal });
    } catch (e) {
      throw new Error(
        e.name === "AbortError"
          ? "ceremony-aborted"
          : e.name === "NotAllowedError"
            ? "Authentication was cancelled or timed out."
            : "Passkey error: " + e.message,
      );
    } finally {
      if (ceremony === controller) ceremony = null;
    }
    return {
      id: c.id,
      rawId: bufferToB64url(c.rawId),
      type: c.type,
      response: {
        authenticatorData: bufferToB64url(c.response.authenticatorData),
        clientDataJSON: bufferToB64url(c.response.clientDataJSON),
        signature: bufferToB64url(c.response.signature),
        userHandle: c.response.userHandle ? bufferToB64url(c.response.userHandle) : null,
      },
    };
  }

  function cancelCeremony() {
    if (ceremony) ceremony.abort();
  }

  // ── Captcha (bollwark) ────────────────────────────────────────────

  // The widget pre-solves invisibly inside the email form; its script and
  // container can land in either order, so poll briefly before scanning.
  function mountCaptcha() {
    if (!hasCaptcha) return;
    let tries = 0;
    const id = setInterval(() => {
      tries++;
      if (window.Bollwark && window.Bollwark.scan) {
        window.Bollwark.scan();
        clearInterval(id);
      } else if (tries > 100) {
        clearInterval(id);
        console.warn("[oxidt-auth] captcha widget failed to mount within 5s");
      }
    }, 50);
  }

  function captchaToken() {
    const el = root.querySelector('input[name="captcha-token"]');
    return el && el.value ? el.value : null;
  }

  function resetCaptcha() {
    const el = root.querySelector('input[name="captcha-token"]');
    if (el) el.value = "";
    const widgets = window.Bollwark && window.Bollwark._instances;
    if (widgets) widgets.forEach((w) => w.reset());
  }

  // Forward the pre-solved token. The email step stays up, so a rejection or
  // timeout lets the user simply resubmit while the widget keeps solving.
  async function completeCaptcha() {
    let token = null;
    for (let i = 0; i < 60 && !token; i++) {
      token = captchaToken();
      if (!token) await sleep(200);
    }
    if (!token) {
      showError("Verification is still loading. Please wait a moment and try again.");
      setLoading(false);
      return;
    }
    try {
      const resp = await postJson("/auth/session/captcha/verify", { captcha_token: token });
      if (resp.success) {
        // The token is spent. A fresh one lets Back and another address
        // verify again instead of failing on the consumed challenge.
        resetCaptcha();
        showError(null);
        show("otp");
        setLoading(false);
        return;
      }
      showError(resp.error || "Verification failed");
    } catch (e) {
      showError(e.message);
    }
    resetCaptcha();
    setLoading(false);
  }

  // ── Flow ──────────────────────────────────────────────────────────

  function proceedAfterLogin(resp) {
    if (resp.needs_tos_acceptance === true) {
      show("tos");
      setLoading(false);
    } else if (resp.redirect_url) {
      show("success");
      window.location.assign(resp.redirect_url);
    }
  }

  // Run the ceremony against the options `/auth/session/start` returned. A
  // failure stays on the passkey step with the error; "Back" starts over.
  async function triggerPasskey() {
    const mine = ++attempt;
    const stale = () => attempt !== mine;
    let assertion;
    try {
      assertion = await getPasskey(passkeyOptions);
    } catch (e) {
      if (stale() || e.message === "ceremony-aborted") return;
      showError(
        isCancel(e.message)
          ? "Passkey authentication was cancelled."
          : "Passkey authentication failed: " + e.message,
      );
      return;
    }
    if (stale()) return;
    show("verifying");
    try {
      const resp = await postJson("/auth/session/passkey/verify", {
        credential_assertion_data: assertion,
      });
      if (stale()) return;
      if (resp.success) return proceedAfterLogin(resp);
      showError(resp.error || "Verification failed");
    } catch (e) {
      if (stale()) return;
      showError(e.message);
    }
    show("passkey");
    setLoading(false);
  }

  async function onEmailSubmit(ev) {
    ev.preventDefault();
    const value = $('[name="email"]').value.trim().toLowerCase();
    clearAlerts();
    if (!value || !value.includes("@")) {
      showError("Please enter a valid email address.");
      return;
    }
    show("detecting");
    setLoading(true);
    $$("[data-email]").forEach((el) => (el.textContent = value));
    try {
      const body = { email: value };
      if (redirectUrl) body.redirect_url = redirectUrl;
      const resp = await postJson("/auth/session/start", body);
      $("[data-new-user]").hidden = !resp.is_new_user;
      $('[data-action="use-password"]').hidden = !resp.has_password;
      if (resp.captcha_required === true) {
        show("email");
        if (hasCaptcha) {
          await completeCaptcha();
        } else {
          // The server asked for a captcha the page cannot mount: `captcha`
          // was not passed to `ferriskey_login_page`.
          showError("Verification is unavailable. Please try again later.");
          setLoading(false);
        }
      } else if (resp.public_key_options) {
        passkeyOptions = resp.public_key_options;
        show("passkey");
        setLoading(false);
        triggerPasskey();
      } else if (resp.has_password) {
        show("password");
        setLoading(false);
      } else if (resp.otp_sent) {
        show("otp");
        setLoading(false);
      } else {
        showError("Unexpected response from server");
        show("email");
        setLoading(false);
      }
    } catch (e) {
      showError(e.message);
      show("email");
      setLoading(false);
    }
  }

  async function onOtpSubmit(ev) {
    ev.preventDefault();
    const code = $('[name="otp"]').value.trim();
    clearAlerts();
    if (!code) {
      showError("Please enter the verification code.");
      return;
    }
    setLoading(true);
    show("verifying");
    try {
      const resp = await postJson("/auth/session/otp/verify", { code });
      if (resp.success) return proceedAfterLogin(resp);
      showError(resp.error || "Verification failed");
    } catch (e) {
      showError(e.message);
    }
    show("otp");
    setLoading(false);
  }

  async function onPasswordSubmit(ev) {
    ev.preventDefault();
    const field = $('[name="password"]');
    const password = field.value;
    clearAlerts();
    if (!password) {
      showError("Please enter your password.");
      return;
    }
    setLoading(true);
    show("verifying");
    try {
      const resp = await postJson("/auth/session/password/verify", { password });
      field.value = "";
      if (resp.success) return proceedAfterLogin(resp);
      showError(resp.error || "Password verification failed");
    } catch (e) {
      // Whatever happened, the field does not keep the secret.
      field.value = "";
      showError(e.message);
    }
    show("password");
    setLoading(false);
  }

  const actions = {
    back() {
      attempt++;
      cancelCeremony();
      clearAlerts();
      $('[name="otp"]').value = "";
      $('[name="password"]').value = "";
      show("email");
      setLoading(false);
    },
    "use-password"() {
      clearAlerts();
      $('[name="password"]').value = "";
      show("password");
    },
    async resend() {
      setLoading(true);
      clearAlerts();
      try {
        const resp = await postJson("/auth/session/otp/resend");
        if (resp.success) showSuccess("A new code has been sent to your email.");
        else showError(resp.error || "Failed to resend code");
      } catch (e) {
        showError(e.message);
      }
      setLoading(false);
    },
    async "tos-accept"() {
      setLoading(true);
      showError(null);
      try {
        const resp = await postJson("/auth/session/accept-tos");
        if (resp.success) return proceedAfterLogin(resp);
        showError(resp.error || "Failed to accept terms");
      } catch (e) {
        showError(e.message);
      }
      setLoading(false);
    },
  };

  // ── Wiring ────────────────────────────────────────────────────────

  root.addEventListener("click", (ev) => {
    const button = ev.target.closest("[data-action]");
    if (button && !button.disabled) actions[button.dataset.action]();
  });
  $('[data-form="email"]').addEventListener("submit", onEmailSubmit);
  $('[data-form="otp"]').addEventListener("submit", onOtpSubmit);
  $('[data-form="password"]').addEventListener("submit", onPasswordSubmit);
  $("[data-tos-check]").addEventListener("change", updateTerms);
  // Leaving the page must not leave a ceremony blocking the document.
  window.addEventListener("pagehide", cancelCeremony);

  // The steps ship disabled, so a submit before this script ran can't fall
  // through to a native GET that reloads the page.
  $("[data-steps]").disabled = false;
  show(root.dataset.start === "tos" ? "tos" : "email");
  setLoading(false);
})();
