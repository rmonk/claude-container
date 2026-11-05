// The gate loads this into ttyd's page, ahead of ttyd's own script. When the terminal's
// websocket closes (the gate closes it when the session expires) and this browser is no
// longer signed in, go to the sign-in page rather than letting ttyd reconnect forever.
(() => {
  const check = async () => {
    try {
      const res = await fetch("/auth/check", { cache: "no-store" });
      if (res.status === 401) location.replace("/auth/login");
    } catch {} // offline: ttyd retries, and the next close checks again
  };
  const Native = window.WebSocket;
  window.WebSocket = class extends Native {
    constructor(...args) {
      super(...args);
      this.addEventListener("close", check);
    }
  };
})();
