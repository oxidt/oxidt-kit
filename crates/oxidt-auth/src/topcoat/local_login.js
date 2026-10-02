// Drives the Topcoat `local_login_page`. A port of the Dioxus `LocalLoginPage`
// (local_login_page.rs): same endpoints, same steps, same ceremony guards.
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
  const webauthn = !!(navigator.credentials && navigator.credentials.create);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const isCancel = (msg) => msg.includes("cancelled") || msg.includes("timed out");

  let step = "email";
  let email = "";
  let loading = false;
  let passkeyOptions = null;
  let pendingRedirect = null;
  let offerAfterTerms = false;
  // Ceremony generation counter: bumped by every ceremony start and by any
  // action that abandons one, so a late-resolving ceremony can't act on a flow
  // the user has left.
  let attempt = 0;
  let condRunning = false;
  let condDisabled = false;
  let condAbort = null;
  let condPending = null;

  // ── UI state ──────────────────────────────────────────────────────

  function show(name) {
    step = name;
    $$("[data-step]").forEach((el) => (el.hidden = el.dataset.step !== name));
    const focus = $(`[data-step="${name}"] [autofocus]`);
    if (focus) focus.focus();
    if (name === "email") {
      mountCaptcha();
      armConditional();
    }
  }

  function setLoading(on) {
    loading = on;
    $$("button").forEach((b) => (b.disabled = on));
    $$("[data-spinner]").forEach((s) => (s.hidden = !on));
    updateTerms();
    if (!on && step === "email") armConditional();
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

  function emailError(msg) {
    const el = $("[data-email-error]");
    el.hidden = !msg;
    if (msg) el.textContent = tr(msg);
    $('[name="email"]').classList.toggle("input-error", !!msg);
  }

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

  // Server options arrive as the W3C JSON shape; tolerate a `publicKey` wrapper.
  function requestOptions(raw, discoverable) {
    const options = { ...(raw.publicKey || raw) };
    if (options.challenge) options.challenge = b64urlToBuffer(options.challenge);
    if (discoverable) {
      options.allowCredentials = [];
    } else if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((c) => ({
        ...c,
        id: b64urlToBuffer(c.id),
      }));
    }
    return options;
  }

  function assertionJson(c) {
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

  async function getPasskey(raw) {
    if (!navigator.credentials || !navigator.credentials.get) {
      throw new Error("Passkeys are not supported in this browser or context.");
    }
    try {
      const c = await navigator.credentials.get({ publicKey: requestOptions(raw, false) });
      return assertionJson(c);
    } catch (e) {
      throw new Error(
        e.name === "NotAllowedError"
          ? "Authentication was cancelled or timed out."
          : "Passkey error: " + e.message,
      );
    }
  }

  async function getPasskeyConditional(raw) {
    if (
      !window.PublicKeyCredential ||
      !PublicKeyCredential.isConditionalMediationAvailable ||
      !(await PublicKeyCredential.isConditionalMediationAvailable())
    ) {
      throw new Error("conditional-unsupported");
    }
    abortConditionalNow();
    const controller = new AbortController();
    condAbort = controller;
    let release;
    const pending = new Promise((r) => (release = r));
    condPending = pending;
    try {
      const c = await navigator.credentials.get({
        publicKey: requestOptions(raw, true),
        mediation: "conditional",
        signal: controller.signal,
      });
      return assertionJson(c);
    } catch (e) {
      throw new Error(
        e.name === "AbortError"
          ? "conditional-aborted"
          : e.name === "NotAllowedError"
            ? "Authentication was cancelled or timed out."
            : "Passkey error: " + e.message,
      );
    } finally {
      if (condAbort === controller) condAbort = null;
      if (condPending === pending) condPending = null;
      release();
    }
  }

  function abortConditionalNow() {
    if (condAbort) condAbort.abort();
    condAbort = null;
  }

  // Abort the parked autofill ceremony and wait (up to ~2s) until the browser
  // has released it: a modal request issued before that is rejected with
  // "A request is already pending".
  async function abortConditional() {
    const pending = condPending;
    abortConditionalNow();
    if (pending) await Promise.race([pending, sleep(2000)]);
  }

  async function createPasskey(raw) {
    if (!navigator.credentials || !navigator.credentials.create) {
      throw new Error("Passkeys are not supported in this browser or context.");
    }
    const options = { ...(raw.publicKey || raw) };
    if (options.challenge) options.challenge = b64urlToBuffer(options.challenge);
    if (options.user && typeof options.user.id === "string") {
      options.user = { ...options.user, id: b64urlToBuffer(options.user.id) };
    }
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((c) => ({
        ...c,
        id: b64urlToBuffer(c.id),
      }));
    }
    let c;
    try {
      c = await navigator.credentials.create({ publicKey: options });
    } catch (e) {
      throw new Error(
        e.name === "NotAllowedError"
          ? "Passkey creation was cancelled or timed out."
          : "Passkey creation error: " + e.message,
      );
    }
    return {
      id: c.id,
      rawId: bufferToB64url(c.rawId),
      type: c.type,
      response: {
        attestationObject: bufferToB64url(c.response.attestationObject),
        clientDataJSON: bufferToB64url(c.response.clientDataJSON),
        transports: (c.response.getTransports && c.response.getTransports()) || [],
      },
    };
  }

  async function enrollPasskey() {
    const opts = await postJson("/auth/passkey/enroll/options");
    const credential = await createPasskey(opts.options);
    const resp = await postJson("/auth/passkey/enroll/verify", { credential, name: null });
    if (!resp.success) throw new Error(resp.error || "Passkey enrollment failed");
  }

  // Storage errors (private mode) count as dismissed, so the prompt never nags.
  function promptDismissed() {
    try {
      return localStorage.getItem("auth_passkey_prompt_dismissed") === "1";
    } catch (_) {
      return true;
    }
  }

  function dismissPrompt() {
    try {
      localStorage.setItem("auth_passkey_prompt_dismissed", "1");
    } catch (_) {}
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

  function finish(url) {
    show("success");
    window.location.assign(url);
  }

  // The last fork before the redirect: the one-time passkey-enrollment offer
  // when the server says the account has none, else straight on.
  function routeAfterTerms(url, offerPasskey) {
    if (offerPasskey && webauthn && !promptDismissed()) {
      pendingRedirect = url;
      show("offer");
      setLoading(false);
    } else {
      finish(url);
    }
  }

  function proceedAfterLogin(resp) {
    if (resp.needs_tos_acceptance === true) {
      offerAfterTerms = resp.offer_passkey === true;
      show("tos");
      setLoading(false);
      return;
    }
    if (resp.redirect_url) routeAfterTerms(resp.redirect_url, resp.offer_passkey === true);
  }

  // Conditional-UI passkeys: while the email step shows, park a discoverable
  // request behind the field so stored passkeys appear in its autofill. A
  // background pre-warm the user never asked for, so failures stay silent.
  async function armConditional() {
    if (step !== "email" || condRunning || condDisabled || loading) return;
    condRunning = true;
    const mine = attempt;
    const stale = () => attempt !== mine;
    try {
      const opts = await postJson("/auth/session/passkey/conditional/options");
      if (stale()) return;
      const assertion = await getPasskeyConditional(opts.options);
      if (stale()) return;
      show("verifying");
      const resp = await postJson("/auth/session/passkey/verify", {
        credential_assertion_data: assertion,
      });
      if (stale()) return;
      if (resp.success) {
        proceedAfterLogin(resp);
      } else {
        show("email");
        throw new Error(resp.error || "Passkey verification failed");
      }
    } catch (e) {
      // Aborted is expected on email submit; anything else means stop retrying.
      if (e.message !== "conditional-aborted") condDisabled = true;
    } finally {
      condRunning = false;
    }
  }

  // Run the modal ceremony against the options `/auth/session/start` returned.
  // Failure or cancel lands on the retry step; no OTP is mailed unasked.
  async function triggerPasskey() {
    if (!passkeyOptions) {
      showError("No passkey challenge available");
      show("email");
      return;
    }
    const mine = ++attempt;
    const stale = () => attempt !== mine;
    try {
      const assertion = await getPasskey(passkeyOptions);
      if (stale()) return;
      show("verifying");
      const resp = await postJson("/auth/session/passkey/verify", {
        credential_assertion_data: assertion,
      });
      if (stale()) return;
      if (resp.success) return proceedAfterLogin(resp);
      throw new Error(resp.error || "Verification failed");
    } catch (e) {
      if (stale()) return;
      showError(isCancel(e.message) ? null : e.message);
      show("passkey-retry");
      setLoading(false);
    }
  }

  async function onEmailSubmit(ev) {
    ev.preventDefault();
    const value = $('[name="email"]').value.trim().toLowerCase();
    if (!value || !value.includes("@")) {
      emailError("Please enter a valid email address.");
      return;
    }
    emailError(null);
    clearAlerts();
    // From here the flow is email-bound: a late autofill pick must not act.
    attempt++;
    setLoading(true);
    email = value;
    $$("[data-email]").forEach((el) => (el.textContent = value));
    try {
      await abortConditional();
      const body = { email: value };
      if (redirectUrl) body.redirect_url = redirectUrl;
      const resp = await postJson("/auth/session/start", body);
      $("[data-new-user]").hidden = !resp.is_new_user;
      $('[data-action="use-code"][data-otp-only]').hidden = resp.otp === false;
      if (resp.captcha_required === true) {
        await completeCaptcha();
      } else if (resp.public_key_options) {
        passkeyOptions = resp.public_key_options;
        show("passkey");
        setLoading(false);
        triggerPasskey();
      } else if (resp.password) {
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
    if (!code) {
      showError("Please enter the verification code.");
      showSuccess(null);
      return;
    }
    setLoading(true);
    clearAlerts();
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
    if (!password) {
      showError("Please enter your password.");
      return;
    }
    setLoading(true);
    clearAlerts();
    try {
      const resp = await postJson("/auth/session/password/verify", { email, password });
      field.value = "";
      if (resp.success) return proceedAfterLogin(resp);
      showError(resp.error || "Sign-in failed");
    } catch (e) {
      // Whatever happened, the field does not keep the secret.
      field.value = "";
      showError(e.message);
    }
    setLoading(false);
  }

  const actions = {
    async passkey() {
      // Discoverable modal ceremony: the resident key names the account.
      showError(null);
      emailError(null);
      attempt++;
      show("passkey");
      await abortConditional();
      const mine = attempt;
      const stale = () => attempt !== mine;
      try {
        const opts = await postJson("/auth/session/passkey/conditional/options");
        const assertion = await getPasskey(opts.options);
        if (stale()) return;
        show("verifying");
        const resp = await postJson("/auth/session/passkey/verify", {
          credential_assertion_data: assertion,
        });
        if (stale()) return;
        if (resp.success) return proceedAfterLogin(resp);
        throw new Error(resp.error || "Passkey verification failed");
      } catch (e) {
        if (stale()) return;
        if (!isCancel(e.message)) showError(e.message);
        show("email");
      }
    },
    async "use-code"() {
      attempt++;
      setLoading(true);
      clearAlerts();
      try {
        await postJson("/auth/session/passkey-fallback-otp");
        showSuccess("Verification code sent to your email.");
        $('[name="password"]').value = "";
        $('[name="otp"]').value = "";
        show("otp");
      } catch (e) {
        showError(e.message);
        show("email");
      }
      setLoading(false);
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
    "passkey-back"() {
      attempt++;
      clearAlerts();
      setLoading(false);
      show("email");
    },
    retry() {
      showError(null);
      show("passkey");
      triggerPasskey();
    },
    back() {
      clearAlerts();
      emailError(null);
      $('[name="otp"]').value = "";
      $('[name="password"]').value = "";
      show("email");
    },
    async "offer-add"() {
      setLoading(true);
      showError(null);
      try {
        await enrollPasskey();
        setLoading(false);
        finish(pendingRedirect);
      } catch (e) {
        showError(e.message);
        setLoading(false);
      }
    },
    "offer-skip"() {
      dismissPrompt();
      showError(null);
      finish(pendingRedirect);
    },
    async "tos-accept"() {
      setLoading(true);
      showError(null);
      try {
        const resp = await postJson("/auth/session/accept-tos");
        if (resp.success) {
          if (resp.redirect_url) routeAfterTerms(resp.redirect_url, offerAfterTerms);
        } else {
          showError(resp.error || "Failed to accept terms");
        }
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
  $('[name="email"]').addEventListener("input", () => emailError(null));
  $("[data-tos-check]").addEventListener("change", updateTerms);
  // Leaving the page must not leave a parked ceremony blocking the document.
  window.addEventListener("pagehide", abortConditionalNow);

  if (webauthn) $("[data-webauthn]").hidden = false;
  // The form ships disabled, so a submit before this script ran can't fall
  // through to a native GET that reloads the page.
  $("fieldset").disabled = false;
  show("email");
  setLoading(false);
})();
