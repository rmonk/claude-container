// Passkey sign-in and registration. The server's options use base64url for binary
// fields; WebAuthn needs ArrayBuffers, and the server wants base64url back.
const fromB64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)).buffer;
const toB64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const status = document.getElementById("status");

async function post(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

function run(button, fn) {
  button.addEventListener("click", async () => {
    button.disabled = true;
    status.textContent = "";
    try {
      const result = await fn();
      if (result) location.href = result.next || "/";
      else button.disabled = false; // cancelled in a dialog
    } catch (e) {
      status.textContent = e.name === "NotAllowedError" ? "Cancelled or timed out." : e.message;
      button.disabled = false;
    }
  });
}

const login = document.getElementById("login");
if (login) run(login, async () => {
  const { publicKey: o } = await post("/auth/login/begin");
  o.challenge = fromB64(o.challenge);
  (o.allowCredentials || []).forEach((c) => (c.id = fromB64(c.id)));
  const cred = await navigator.credentials.get({ publicKey: o });
  return post("/auth/login/finish", {
    id: cred.id, rawId: toB64(cred.rawId), type: cred.type,
    response: {
      clientDataJSON: toB64(cred.response.clientDataJSON),
      authenticatorData: toB64(cred.response.authenticatorData),
      signature: toB64(cred.response.signature),
      userHandle: cred.response.userHandle && toB64(cred.response.userHandle),
    },
  });
});

const register = document.getElementById("register");
if (register) run(register, async () => {
  const code = document.getElementById("code");
  const name = document.getElementById("name").value;
  const { publicKey: o } = await post("/auth/register/begin", { code: code ? code.value : "", name });
  o.challenge = fromB64(o.challenge);
  o.user.id = fromB64(o.user.id);
  (o.excludeCredentials || []).forEach((c) => (c.id = fromB64(c.id)));
  const cred = await navigator.credentials.create({ publicKey: o });
  return post("/auth/register/finish", {
    id: cred.id, rawId: toB64(cred.rawId), type: cred.type,
    response: {
      clientDataJSON: toB64(cred.response.clientDataJSON),
      attestationObject: toB64(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
  });
});

// Manage page: rename, remove, sign out other browsers, WebDAV tokens.
document.querySelectorAll("[data-action]").forEach((button) => run(button, async () => {
  const { action, id, name } = button.dataset;
  if (action === "rename") {
    const next = prompt("New name for this passkey:", name);
    if (next === null) return null;
    return post("/auth/manage/rename", { id, name: next });
  }
  if (action === "remove") {
    if (!confirm(`Remove "${name}"? Browsers signed in with it are signed out, and it can no longer sign in here.`)) return null;
    return post("/auth/manage/remove", { id });
  }
  if (action === "token-create") {
    const tokenName = prompt("Name for this token (e.g. the machine it's for):");
    if (tokenName === null) return null;
    const { token } = await post("/auth/manage/token-create", { name: tokenName });
    // Shown once, in place; "Done" reloads the page with the token listed.
    const box = document.getElementById("newtoken");
    box.querySelector("textarea").value =
      `rclone config create claude webdav url=${box.dataset.url} vendor=other bearer_token=${token}\n` +
      "rclone mount claude: ~/claude-work --vfs-cache-mode writes";
    box.hidden = false;
    button.hidden = true;
    return null;
  }
  if (action === "token-revoke") {
    if (!confirm(`Revoke "${name}"? Anything using it loses access at once.`)) return null;
    return post("/auth/manage/token-revoke", { id });
  }
  if (!confirm("Sign out every other browser? This one stays signed in.")) return null;
  return post("/auth/manage/signout-others");
}));
