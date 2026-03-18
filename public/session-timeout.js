(function () {
  if (window.__assetSessionTimeoutInitialized) {
    return;
  }
  window.__assetSessionTimeoutInitialized = true;

  const DEFAULT_INACTIVITY_TIMEOUT = 30 * 60 * 1000;
  const DEFAULT_WARNING_WINDOW = 5 * 60 * 1000;
  const KEEPALIVE_THROTTLE_MS = 60 * 1000;
  const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'];

  let sessionConfig = null;
  let inactivityTimer = null;
  let warningTimer = null;
  let countdownTimer = null;
  let inactivityDeadline = 0;
  let lastKeepaliveAt = 0;
  let warningShown = false;
  let sessionClosed = false;

  function getModalElements() {
    let overlay = document.getElementById('timeoutModalOverlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'timeoutModalOverlay';
      overlay.className = 'profile-modal-overlay';
      overlay.style.display = 'none';
      overlay.style.position = 'fixed';
      overlay.style.inset = '0';
      overlay.style.zIndex = '9999';
      overlay.style.background = 'rgba(0, 0, 0, 0.7)';
      overlay.style.alignItems = 'center';
      overlay.style.justifyContent = 'center';
      overlay.innerHTML = [
        '<div class="profile-modal" style="background:#fff;border:2px solid var(--brand-500);max-width:400px;">',
        '  <div class="profile-header" style="background:var(--brand-500);color:#fff;border-radius:8px 8px 0 0;">',
        '    <h3 style="margin:0;font-size:1.3rem;"><i class="bi bi-exclamation-triangle-fill me-2"></i>Session Timeout Warning</h3>',
        '  </div>',
        '  <div class="profile-body" style="text-align:center;padding:2rem;">',
        '    <p style="font-size:1rem;margin-bottom:1rem;color:#333;">Your session will expire due to inactivity in <span id="timeoutCountdown" style="font-weight:bold;color:var(--brand-500);">5:00</span></p>',
        '    <p style="font-size:0.9rem;color:#666;margin-bottom:1.5rem;">Activity such as mouse movements, clicks, or typing will extend your session.</p>',
        '    <div style="display:flex;gap:1rem;">',
        '      <button class="profile-btn" id="continueSessionBtn" type="button" style="flex:1;background:var(--brand-500);color:#fff;border:none;padding:0.75rem;border-radius:4px;cursor:pointer;font-weight:600;">Continue Session</button>',
        '      <button class="profile-btn" id="logoutNowBtn" type="button" style="flex:1;background:#6b7280;color:#fff;border:none;padding:0.75rem;border-radius:4px;cursor:pointer;font-weight:600;">Logout Now</button>',
        '    </div>',
        '  </div>',
        '</div>'
      ].join('');
      document.body.appendChild(overlay);
    }

    return {
      overlay,
      countdown: document.getElementById('timeoutCountdown'),
      continueButton: document.getElementById('continueSessionBtn'),
      logoutButton: document.getElementById('logoutNowBtn')
    };
  }

  function clearTimers() {
    if (inactivityTimer) {
      clearTimeout(inactivityTimer);
      inactivityTimer = null;
    }
    if (warningTimer) {
      clearTimeout(warningTimer);
      warningTimer = null;
    }
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
  }

  function hideWarning() {
    const { overlay } = getModalElements();
    overlay.style.display = 'none';
    warningShown = false;
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
  }

  function redirectToLogin(reason) {
    window.location.href = '/login.html?reason=' + encodeURIComponent(reason);
  }

  async function fetchCsrfToken() {
    const csrfResponse = await fetch('/api/csrf-token', {
      credentials: 'include',
      cache: 'no-store'
    });

    if (!csrfResponse.ok) {
      throw new Error(`CSRF token request failed with ${csrfResponse.status}`);
    }

    const csrfPayload = await csrfResponse.json();
    if (!csrfPayload || !csrfPayload.csrfToken) {
      throw new Error('CSRF token missing from response');
    }

    return csrfPayload.csrfToken;
  }

  async function logout(reason) {
    if (sessionClosed) {
      return;
    }

    sessionClosed = true;
    clearTimers();
    hideWarning();

    try {
      const csrfToken = await fetchCsrfToken();
      await fetch('/api/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'csrf-token': csrfToken
        }
      });
    } catch (error) {
      console.error('Logout request failed:', error);
    }

    redirectToLogin(reason);
  }

  function updateCountdown() {
    const { countdown } = getModalElements();
    const remainingMs = Math.max(0, inactivityDeadline - Date.now());
    const minutes = Math.floor(remainingMs / 60000);
    const seconds = Math.floor((remainingMs % 60000) / 1000);

    if (countdown) {
      countdown.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
    }

    if (remainingMs <= 0) {
      logout('Session expired due to inactivity');
    }
  }

  function showWarning() {
    if (warningShown || sessionClosed) {
      return;
    }

    warningShown = true;
    const { overlay } = getModalElements();
    overlay.style.display = 'flex';
    updateCountdown();
    countdownTimer = window.setInterval(updateCountdown, 1000);
  }

  function scheduleTimers() {
    if (!sessionConfig || sessionClosed) {
      return;
    }

    clearTimers();
    inactivityDeadline = Date.now() + sessionConfig.inactivityTimeout;

    warningTimer = window.setTimeout(showWarning, sessionConfig.warningTimeout);
    inactivityTimer = window.setTimeout(() => {
      logout('Session expired due to inactivity');
    }, sessionConfig.inactivityTimeout);
  }

  async function keepAlive(force) {
    if (sessionClosed) {
      return false;
    }

    const now = Date.now();
    if (!force && now - lastKeepaliveAt < KEEPALIVE_THROTTLE_MS) {
      return true;
    }

    try {
      const response = await fetch('/api/auth-status', {
        credentials: 'include',
        cache: 'no-store',
        headers: {
          Accept: 'application/json'
        }
      });

      if (response.status === 401) {
        redirectToLogin('Session expired due to inactivity');
        sessionClosed = true;
        return false;
      }

      const payload = await response.json();
      if (!response.ok || !payload || payload.authenticated === false) {
        redirectToLogin('Your session has ended');
        sessionClosed = true;
        return false;
      }

      lastKeepaliveAt = now;
      return true;
    } catch (error) {
      console.error('Session keepalive failed:', error);
      return false;
    }
  }

  function handleActivity() {
    if (!sessionConfig || sessionClosed) {
      return;
    }

    hideWarning();
    scheduleTimers();
    keepAlive(false);
  }

  async function continueSession() {
    const isAlive = await keepAlive(true);
    if (!isAlive) {
      return;
    }

    hideWarning();
    scheduleTimers();
  }

  async function loadSessionConfig() {
    const response = await fetch('/api/session-config', {
      credentials: 'include',
      cache: 'no-store'
    });

    if (!response.ok) {
      throw new Error(`Session config request failed with ${response.status}`);
    }

    const payload = await response.json();
    const inactivityTimeout = Number.parseInt(payload.inactivityTimeout, 10) || DEFAULT_INACTIVITY_TIMEOUT;
    const warningTimeout = Number.parseInt(payload.warningTimeout, 10)
      || Math.max(inactivityTimeout - DEFAULT_WARNING_WINDOW, DEFAULT_WARNING_WINDOW);

    return {
      inactivityTimeout,
      warningTimeout: Math.min(warningTimeout, inactivityTimeout)
    };
  }

  function bindModalActions() {
    const { continueButton, logoutButton } = getModalElements();

    if (continueButton && !continueButton.dataset.bound) {
      continueButton.dataset.bound = 'true';
      continueButton.addEventListener('click', continueSession);
    }

    if (logoutButton && !logoutButton.dataset.bound) {
      logoutButton.dataset.bound = 'true';
      logoutButton.addEventListener('click', function () {
        logout('User logged out from timeout warning');
      });
    }
  }

  async function initialize() {
    try {
      bindModalActions();
      sessionConfig = await loadSessionConfig();
      const isAlive = await keepAlive(true);
      if (!isAlive) {
        return;
      }

      ACTIVITY_EVENTS.forEach((eventName) => {
        document.addEventListener(eventName, handleActivity, { passive: true });
      });

      document.addEventListener('visibilitychange', function () {
        if (!document.hidden) {
          handleActivity();
        }
      });

      scheduleTimers();
    } catch (error) {
      console.error('Failed to initialize session timeout:', error);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize, { once: true });
  } else {
    initialize();
  }
})();