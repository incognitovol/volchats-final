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

const suEmail = qs("suEmail");
const sendCodeBtn = qs("sendCodeBtn");
const suCode = qs("suCode");
const suUsername = qs("suUsername");
const suGender = qs("suGender");
const suYear = qs("suYear");
const suPass = qs("suPass");
const createBtn = qs("createBtn");
const signupMsg = qs("signupMsg");

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
goSignup.onclick = (e) => { e.preventDefault(); setTab("signup"); };
goLogin.onclick = (e) => { e.preventDefault(); setTab("login"); };

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
  // If they were trying to enter a page, you can expand this later.
  window.location.href = "index.html";
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

loginBtn.onclick = async () => {
  hide(loginMsg);
  loginBtn.disabled = true;

  try{
    const data = await api("/api/auth/login", "POST", {
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

sendCodeBtn.onclick = async () => {
  hide(signupMsg);
  sendCodeBtn.disabled = true;

  try{
    await api("/api/auth/request-code", "POST", { email: suEmail.value.trim() });
    show(signupMsg, "Code sent. Check your UTK email. (If SMTP isn’t set yet, check your server terminal for the code.)", "ok");
  }catch(e){
    show(signupMsg, e.message || "Failed to send code", "err");
  }finally{
    sendCodeBtn.disabled = false;
  }
};

createBtn.onclick = async () => {
  hide(signupMsg);
  createBtn.disabled = true;

  try{
    // (optional) quick verify first for clearer errors
    await api("/api/auth/verify-code", "POST", { email: suEmail.value.trim(), code: suCode.value.trim() });

    await api("/api/auth/register", "POST", {
      email: suEmail.value.trim(),
      code: suCode.value.trim(),
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
