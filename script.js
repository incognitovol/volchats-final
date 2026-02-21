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

// Signup elements (3 steps)
const step1 = document.getElementById("step1");
const step2 = document.getElementById("step2");
const step3 = document.getElementById("step3");

const suEmail = document.getElementById("suEmail");
const sendCodeBtn = document.getElementById("sendCodeBtn");
const signupMsg1 = document.getElementById("signupMsg1");

const suCode = document.getElementById("suCode");
const backToEmailBtn = document.getElementById("backToEmailBtn");
const verifyCodeBtn = document.getElementById("verifyCodeBtn");
const signupMsg2 = document.getElementById("signupMsg2");

const suUsername = document.getElementById("suUsername");
const suGender = document.getElementById("suGender");
const suYear = document.getElementById("suYear");
const suPass = document.getElementById("suPass");
const createBtn = document.getElementById("createBtn");
const signupMsg3 = document.getElementById("signupMsg3");

let pendingTarget = null; // "video.html" or "text.html"
let verifiedOk = false;

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
  hideMsg(signupMsg3);
}

function setStep(n) {
  step1.classList.toggle("active", n === 1);
  step2.classList.toggle("active", n === 2);
  step3.classList.toggle("active", n === 3);

  hideMsg(signupMsg1);
  hideMsg(signupMsg2);
  hideMsg(signupMsg3);
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
async function startChat(target) {
  pendingTarget = target;

  const loggedIn = await checkLoggedIn();
  if (loggedIn) {
    window.location.href = target;
    return;
  }

  // reset modal state
  authBanner.style.display = "none";
  verifiedOk = false;
  setTab("login");
  setStep(1);
  showModal();
}

if (videoBtn) videoBtn.addEventListener("click", () => startChat("video.html"));
if (textBtn) textBtn.addEventListener("click", () => startChat("text.html"));

if (onlineEl) onlineEl.textContent = "0";

// Close behaviors
if (authCloseBtn) authCloseBtn.addEventListener("click", hideModal);
if (authModal) {
  authModal.addEventListener("click", (e) => {
    if (e.target === authModal) hideModal();
  });
}
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && authModal.classList.contains("show")) hideModal();
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

// LOGIN
if (loginBtn) {
  loginBtn.addEventListener("click", async () => {
    hideMsg(loginMsg);
    loginBtn.disabled = true;

    try {
      await api("/api/auth/login", "POST", {
        login: (loginField?.value || "").trim(),
        password: (loginPass?.value || ""),
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
    }
  });
}

// SIGNUP STEP 1: send code
if (sendCodeBtn) {
  sendCodeBtn.addEventListener("click", async () => {
    hideMsg(signupMsg1);
    sendCodeBtn.disabled = true;

    try {
      const email = (suEmail?.value || "").trim();
      await api("/api/auth/request-code", "POST", { email });

      showMsg(signupMsg1, "Code sent. Check your UTK email.", "ok");

      setTimeout(() => {
        setStep(2);
        suCode?.focus();
      }, 400);
    } catch (e) {
      showMsg(signupMsg1, e.message || "Could not send code", "err");
    } finally {
      sendCodeBtn.disabled = false;
    }
  });
}

// SIGNUP STEP 2: back
if (backToEmailBtn) {
  backToEmailBtn.addEventListener("click", () => {
    verifiedOk = false;
    setStep(1);
    suEmail?.focus();
  });
}

// SIGNUP STEP 2: verify code
if (verifyCodeBtn) {
  verifyCodeBtn.addEventListener("click", async () => {
    hideMsg(signupMsg2);
    verifyCodeBtn.disabled = true;

    try {
      const email = (suEmail?.value || "").trim();
      const code = (suCode?.value || "").trim();

      await api("/api/auth/verify-code", "POST", { email, code });
      verifiedOk = true;

      showMsg(signupMsg2, "Verified. Finish your profile.", "ok");

      setTimeout(() => {
        setStep(3);
        suUsername?.focus();
      }, 350);
    } catch (e) {
      verifiedOk = false;
      showMsg(signupMsg2, e.message || "Verification failed", "err");
    } finally {
      verifyCodeBtn.disabled = false;
    }
  });
}

// SIGNUP STEP 3: create account
if (createBtn) {
  createBtn.addEventListener("click", async () => {
    hideMsg(signupMsg3);
    createBtn.disabled = true;

    try {
      if (!verifiedOk) {
        showMsg(signupMsg3, "Verify your email code first.", "err");
        createBtn.disabled = false;
        setStep(2);
        return;
      }

      await api("/api/auth/register", "POST", {
        email: (suEmail?.value || "").trim(),
        code: (suCode?.value || "").trim(),
        username: (suUsername?.value || "").trim(),
        gender: suGender?.value || "",
        classYear: suYear?.value || "",
        password: suPass?.value || "",
      });

      showMsg(signupMsg3, "Account created. Sending you in…", "ok");

      setTimeout(() => {
        hideModal();
        window.location.href = pendingTarget || "index.html";
      }, 450);
    } catch (e) {
      showMsg(signupMsg3, e.message || "Signup failed", "err");
    } finally {
      createBtn.disabled = false;
    }
  });
}

// hydrate profile on load
hydrateProfile();
