function qs(id){ return document.getElementById(id); }

const tabLogin = qs("tabLogin");
const tabSignup = qs("tabSignup");
const secLogin = qs("secLogin");
const secSignup = qs("secSignup");

const banBox = qs("banBox");

const loginField = qs("loginField");
const loginPass = qs("loginPass");
const loginBtn = qs("loginBtn");
const loginMsg = qs("loginMsg");

const msBtn = qs("msBtn");
const signupMsg = qs("signupMsg");

const postOauthFields = qs("postOauthFields");
const suEmail = qs("suEmail");
const suUsername = qs("suUsername");
const suGender = qs("suGender");
const suYear = qs("suYear");
const suPass = qs("suPass");
const createBtn = qs("createBtn");

const goSignup = qs("goSignup");
const goLogin = qs("goLogin");

function show(el, text, kind){
  el.style.display = "block";
  el.classList.remove("err","ok");
  if(kind) el.classList.add(kind);
  el.textContent = text;
}
function hide(el){ el.style.display = "none"; }

function setTab(which){
  const login = which === "login";
  tabLogin.classList.toggle("active", login);
  tabSignup.classList.toggle("active", !login);
  secLogin.classList.toggle("active", login);
  secSignup.classList.toggle("active", !login);
  hide(loginMsg);
  hide(signupMsg);
}

tabLogin.onclick = () => setTab("login");
tabSignup.onclick = () => setTab("signup");
if(goSignup) goSignup.onclick = (e) => { e.preventDefault(); setTab("signup"); };
if(goLogin) goLogin.onclick = (e) => { e.preventDefault(); setTab("login"); };

async function api(path, method, body){
  const res = await fetch(path, {
    method,
    headers: { "Content-Type":"application/json" },
    body: body ? JSON.stringify(body) : undefined
  });
  let data = null;
  try{ data = await res.json(); }catch{}
  if(!res.ok){
    const msg = data?.error || ("HTTP " + res.status);
    const err = new Error(msg);
    err.data = data;
    throw err;
  }
  return data;
}

function redirectAfterLogin(){
  window.location.href = "index.html";
}

// ======== OAuth state ========
let OAUTH_VERIFIED = false;

function applyOauthVerifiedUI(email){
  OAUTH_VERIFIED = true;

  if (postOauthFields) postOauthFields.style.display = "block";
  if (suEmail){
    suEmail.value = email || "";
  }
  if (createBtn){
    createBtn.disabled = false;
  }

  show(
    signupMsg,
    "Microsoft verified. Now choose your username + profile info and create your account.",
    "ok"
  );
}

// show ban message if redirected
(function(){
  const p = new URLSearchParams(location.search);
  if(p.get("banned") === "1"){
    const until = p.get("until") || "";
    const reason = p.get("reason") || "Banned";
    show(banBox, `You are banned until ${until}. Reason: ${reason}`, "err");
  }
})();

// handle OAuth return (?oauth=1)
(async function(){
  try{
    const p = new URLSearchParams(location.search);
    if(p.get("oauth") !== "1") return;

    setTab("signup");
    hide(signupMsg);
    show(signupMsg, "Finishing Microsoft verification…", null);

    const r = await fetch("/api/auth/oauth-status");
    const j = await r.json().catch(()=>null);

    if(!r.ok || !j || !j.ok){
      show(
        signupMsg,
        j?.error || "Microsoft verification failed. Please try again.",
        "err"
      );
      return;
    }

    applyOauthVerifiedUI(j.email);
  }catch(e){
    show(signupMsg, "Microsoft verification failed. Please try again.", "err");
  }
})();

// Microsoft button click
if(msBtn){
  msBtn.onclick = (e) => {
    e.preventDefault();
    hide(signupMsg);
    show(signupMsg, "Redirecting to Microsoft…", null);
    window.location.href = "/auth/microsoft";
  };
}

// Login
loginBtn.onclick = async () => {
  hide(loginMsg);
  loginBtn.disabled = true;

  try{
    await api("/api/auth/login", "POST", {
      login: loginField.value.trim(),
      password: loginPass.value
    });

    show(loginMsg, "Logged in. Redirecting…", "ok");
    setTimeout(redirectAfterLogin, 400);
  }catch(e){
    if(e.data?.reason && e.data?.until){
      show(loginMsg, `You are banned until ${e.data.until}. Reason: ${e.data.reason}`, "err");
    }else{
      show(loginMsg, e.message || "Login failed", "err");
    }
  }finally{
    loginBtn.disabled = false;
  }
};

// Create account (OAuth-only)
createBtn.onclick = async () => {
  hide(signupMsg);
  createBtn.disabled = true;

  try{
    if(!OAUTH_VERIFIED){
      show(signupMsg, "Please verify with Microsoft first.", "err");
      createBtn.disabled = false;
      return;
    }

    await api("/api/auth/register-oauth", "POST", {
      username: suUsername.value.trim(),
      gender: suGender.value,
      classYear: suYear.value,
      password: suPass.value
    });

    show(signupMsg, "Account created. Redirecting…", "ok");
    setTimeout(redirectAfterLogin, 500);
  }catch(e){
    show(signupMsg, e.message || "Signup failed", "err");
  }finally{
    createBtn.disabled = false;
  }
};
