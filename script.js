const videoBtn = document.getElementById("videoChatBtn");
const textBtn = document.getElementById("textChatBtn");
const onlineEl = document.getElementById("onlineCount");

// Profile dropdown elements (home page)
const profileWrap = document.getElementById("profileWrap");
const profileBtn = document.getElementById("profileBtn");
const profileMenu = document.getElementById("profileMenu");
const profileBtnName = document.getElementById("profileBtnName");
const pmUsername = document.getElementById("pmUsername");
const pmEmail = document.getElementById("pmEmail");
const pmLogout = document.getElementById("pmLogout");

// Modal elements
const authModal = document.getElementById("authModal");
const authCloseBtn = document.getElementById("authCloseBtn");
const authBanner = document.getElementById("authBanner");

const tabLogin = document.getElementById("tabLogin");
const tabSignup = document.getElementById("tabSignup");
const panelLogin = document.getElementById("panelLogin");
const panelSignup = document.getElementById("panelSignup");

const goSignup = document.getElementById("goSignup");
const goLogin = document.getElementById("goLogin");

// Login elements
const loginField = document.getElementById("loginField");
const loginPass = document.getElementById("loginPass");
const loginBtn = document.getElementById("loginBtn");
const loginMsg = document.getElementById("loginMsg");

let LOGIN_LOCK = false;

// Signup elements (Microsoft-first, 2 steps)
const step1 = document.getElementById("step1"); // Microsoft verify
const step2 = document.getElementById("step2"); // Profile info

const msBtn = document.getElementById("msBtn");
const signupMsg1 = document.getElementById("signupMsg1");
const signupMsg2 = document.getElementById("signupMsg2");

const suEmail = document.getElementById("suEmail"); // disabled, filled after OAuth
const suUsername = document.getElementById("suUsername");
const suGender = document.getElementById("suGender");
const suYear = document.getElementById("suYear");
const suPass = document.getElementById("suPass");
const createBtn = document.getElementById("createBtn");

let pendingTarget = null; // "video.html" or "text.html"
let OAUTH_VERIFIED = false;

function showModal() {
  authModal.classList.add("show");
  authModal.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
}

function hideModal() {
  authModal.classList.remove("show");
  authModal.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
}

function showMsg(el, text, type) {
  if (!el) return;
  el.style.display = "block";
  el.classList.remove("ok", "err");
  if (type) el.classList.add(type);
  el.textContent = text;
}

function hideMsg(el) {
  if (!el) return;
  el.style.display = "none";
}

function setTab(which) {
  const isLogin = which === "login";
  tabLogin.classList.toggle("active", isLogin);
  tabSignup.classList.toggle("active", !isLogin);
  panelLogin.classList.toggle("active", isLogin);
  panelSignup.classList.toggle("active", !isLogin);

  hideMsg(loginMsg);
  hideMsg(signupMsg1);
  hideMsg(signupMsg2);
}

function setStep(n) {
  if (step1) step1.classList.toggle("active", n === 1);
  if (step2) step2.classList.toggle("active", n === 2);

  hideMsg(signupMsg1);
  hideMsg(signupMsg2);
}

async function api(path, method, body) {
  const res = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });

  let data = null;
  try { data = await res.json(); } catch {}

  if (!res.ok) {
    const err = new Error(data?.error || ("HTTP " + res.status));
    err.data = data;
    throw err;
  }
  return data;
}

async function checkLoggedIn() {
  try {
    const me = await api("/api/me", "GET");
    return !!me?.user?.id;
  } catch {
    return false;
  }
}

/* ---------------------------
   Profile dropdown (home)
----------------------------*/
async function hydrateProfile() {
  if (!profileWrap) return;

  try {
    const me = await api("/api/me", "GET");
    if (me?.user?.username) {
      profileWrap.style.display = "inline-block";
      profileBtnName.textContent = me.user.username;
      pmUsername.textContent = me.user.username;
      pmEmail.textContent = me.user.email || "";
    } else {
      profileWrap.style.display = "none";
    }
  } catch {
    profileWrap.style.display = "none";
  }
}

function closeProfileMenu() {
  if (profileMenu) profileMenu.classList.remove("show");
}
function toggleProfileMenu() {
  if (!profileMenu) return;
  profileMenu.classList.toggle("show");
}

if (profileBtn) {
  profileBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    toggleProfileMenu();
  });
}
document.addEventListener("click", () => {
  closeProfileMenu();
});
if (pmLogout) {
  pmLogout.addEventListener("click", async () => {
    try {
      await api("/api/auth/logout", "POST");
    } catch {}
    closeProfileMenu();
    window.location.reload();
  });
}

/* ---------------------------
   Start chat (requires auth)
----------------------------*/
let STARTCHAT_LOCK = false;

async function startChat(target) {
  if (STARTCHAT_LOCK) return;
  STARTCHAT_LOCK = true;
  
  pendingTarget = target;

  const loggedIn = await checkLoggedIn();
  if (loggedIn) {
    window.location.href = target;
    return;
  }

  // reset modal state
  if (authBanner) authBanner.style.display = "none";

  OAUTH_VERIFIED = false;
  if (suEmail) {
    suEmail.value = "";
    suEmail.disabled = true;
  }

  setTab("login");
  setStep(1);
  showModal();
}

  // allow clicking again after model opens
 setTimeout(() => {
   STARTCHAT_LOCK = false;
 }, 500);

if (videoBtn) videoBtn.addEventListener("click", () => startChat("video.html"));
if (textBtn) textBtn.addEventListener("click", () => startChat("text.html"));

// Microsoft OAuth (signup) button

if (msBtn) {
  msBtn.addEventListener("click", () => {
    const next = pendingTarget || "/";
    window.location.href = `/auth/microsoft?next=${encodeURIComponent(next)}`;
  });
}

if (onlineEl) onlineEl.textContent = "0";

// Close behaviors
if (authCloseBtn) authCloseBtn.addEventListener("click", hideModal);
if (authModal) {
  authModal.addEventListener("click", (e) => {
    if (e.target === authModal) hideModal();
  });
}
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && authModal?.classList.contains("show")) hideModal();
});

// Tabs + quick links
if (tabLogin) tabLogin.addEventListener("click", () => setTab("login"));
if (tabSignup) tabSignup.addEventListener("click", () => { setTab("signup"); setStep(1); });

if (goSignup) goSignup.addEventListener("click", (e) => {
  e.preventDefault();
  setTab("signup");
  setStep(1);
});

if (goLogin) goLogin.addEventListener("click", (e) => {
  e.preventDefault();
  setTab("login");
});

/* ---------------------------
   LOGIN
----------------------------*/
if (loginBtn) {
  loginBtn.addEventListener("click", async () => {

    if (LOGIN_LOCK) return;
    LOGIN_LOCK = true;

    hideMsg(loginMsg);
    loginBtn.disabled = true;

    const loginVal = (loginField?.value || "").trim();
    const passVal = (loginPass?.value || "");

    if (!loginVal || !passVal) {
      showMsg(loginMsg, "Email/username and password required", "err");
      loginBtn.disabled = false;
      LOGIN_LOCK = false;
      return;
    }
  
    const rememberMe = document.getElementById("rememberMe")?.checked || false;

    try {
      await api("/api/auth/login", "POST", {
        login: (loginField?.value || "").trim(),
        password: (loginPass?.value || ""),
        rememberMe: rememberMe
      });

      showMsg(loginMsg, "Logged in. Sending you in…", "ok");

      setTimeout(() => {
        hideModal();
        window.location.href = pendingTarget || "index.html";
      }, 350);
    } catch (e) {
      if (e.data?.reason && e.data?.until) {
        showMsg(loginMsg, `You are banned until ${e.data.until}. Reason: ${e.data.reason}`, "err");
      } else {
        showMsg(loginMsg, e.message || "Login failed", "err");
      }
    } finally {
      loginBtn.disabled = false;
      LOGIN_LOCK = false;  // release lock
    }
  });
}

/* ---------------------------
   MICROSOFT OAUTH (signup step 1)
----------------------------*/
if (msBtn) {
  msBtn.addEventListener("click", (e) => {
    e.preventDefault();
    hideMsg(signupMsg1);
    showMsg(signupMsg1, "Redirecting to Microsoft…", null);
    // server route that starts OAuth
    window.location.href = "/auth/microsoft";
  });
}

// If we return from Microsoft, server should redirect back to index with ?oauth=1
(async function handleOauthReturn() {
  try {
    const p = new URLSearchParams(window.location.search);
    if (p.get("oauth") !== "1") return;

    // open modal directly in signup flow
    pendingTarget = pendingTarget || p.get("next") || null;
    showModal();
    setTab("signup");
    setStep(1);

    hideMsg(signupMsg1);
    showMsg(signupMsg1, "Finishing Microsoft verification…", null);

    const r = await fetch("/api/auth/oauth-status");
    const j = await r.json().catch(() => null);

    if (!r.ok || !j || !j.ok) {
      showMsg(
        signupMsg1,
        j?.error || "Microsoft verification failed. Please try again.",
        "err"
      );
      return;
    }

    // Verified!
    OAUTH_VERIFIED = true;

    // Fill email and move to step 2
    if (suEmail) {
      suEmail.value = j.email || "";
      suEmail.disabled = true;
    }

    showMsg(
      signupMsg1,
      "Microsoft verified. Now finish your profile below.",
      "ok"
    );

    setTimeout(() => {
      setStep(2);
      suUsername?.focus();
    }, 250);

    // clean the URL so refresh doesn't re-run oauth flow
    const cleanUrl = window.location.pathname + (p.get("next") ? `?next=${encodeURIComponent(p.get("next"))}` : "");
    window.history.replaceState({}, "", cleanUrl);
  } catch {
    showMsg(signupMsg1, "Microsoft verification failed. Please try again.", "err");
  }
})();

/* ---------------------------
   CREATE ACCOUNT (signup step 2)
----------------------------*/
if (createBtn) {
  createBtn.addEventListener("click", async () => {
    hideMsg(signupMsg2);
    createBtn.disabled = true;

    try {
      if (!OAUTH_VERIFIED) {
        showMsg(signupMsg2, "Please verify with UTK Microsoft first.", "err");
        setStep(1);
        createBtn.disabled = false;
        return;
      }

      await api("/api/auth/register-oauth", "POST", {
        username: (suUsername?.value || "").trim(),
        gender: suGender?.value || "",
        classYear: suYear?.value || "",
        password: suPass?.value || "",
      });

      showMsg(signupMsg2, "Account created. Sending you in…", "ok");

      setTimeout(() => {
        hideModal();
        window.location.href = pendingTarget || "index.html";
      }, 450);
    } catch (e) {
      showMsg(signupMsg2, e.message || "Signup failed", "err");
    } finally {
      createBtn.disabled = false;
    }
  });
}

// hydrate profile on load
hydrateProfile();
