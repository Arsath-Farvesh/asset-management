(() => {
  const overlay = document.getElementById('profileModalOverlay');
  const content = document.getElementById('profileContent');
  const avatarLarge = document.getElementById('profileAvatarLarge');
  const usernameEl = document.getElementById('profileUsername');
  const roleEl = document.getElementById('profileRoleDisplay');

  if (!overlay || !content || !avatarLarge || !usernameEl || !roleEl) {
    return;
  }

  const state = {
    viewer: null,
    csrfToken: null,
    activeTab: 'profile',
    users: [],
    selectedUserId: null
  };

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function getCsrfToken() {
    if (state.csrfToken) {
      return state.csrfToken;
    }

    const res = await fetch('/api/csrf-token', { credentials: 'include', cache: 'no-store' });
    const data = await res.json();
    state.csrfToken = data.csrfToken;
    return state.csrfToken;
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, {
      credentials: 'include',
      ...options
    });

    let payload = null;
    try {
      payload = await response.json();
    } catch (error) {
      payload = null;
    }

    if (!response.ok) {
      const message = payload?.error || payload?.message || `Request failed: ${response.status}`;
      throw new Error(message);
    }

    return payload;
  }

  function syncNavbarIndicator() {
    let indicator = document.getElementById('authIndicator');
    if (!indicator || !state.viewer) {
      return;
    }

    const replacement = indicator.cloneNode(true);
    indicator.parentNode.replaceChild(replacement, indicator);
    indicator = replacement;

    const userAvatar = document.getElementById('userAvatar');
    const userName = document.getElementById('userName');
    const userRole = document.getElementById('userRole');

    if (userAvatar) {
      userAvatar.textContent = state.viewer.username.charAt(0).toUpperCase();
    }
    if (userName) {
      userName.textContent = state.viewer.username;
    }
    if (userRole) {
      userRole.textContent = String(state.viewer.role || 'user').toUpperCase();
      userRole.className = `user-role role-${state.viewer.role || 'user'}`;
    }

    indicator.style.display = 'flex';
    indicator.addEventListener('click', openProfileModal);
  }

  async function loadViewer() {
    const payload = await fetchJson('/api/auth-status');
    if (!payload.authenticated || !payload.user) {
      return;
    }

    state.viewer = payload.user;
    syncNavbarIndicator();
  }

  async function loadUsers() {
    if (!state.viewer || state.viewer.role !== 'admin') {
      return;
    }

    const payload = await fetchJson('/api/users');
    state.users = payload.users || [];
    if (!state.selectedUserId && state.users.length > 0) {
      state.selectedUserId = state.users[0].id;
    }
  }

  function getSelectedUser() {
    return state.users.find((user) => user.id === state.selectedUserId) || null;
  }

  function renderHeader() {
    const username = state.viewer?.username || 'User';
    const role = state.viewer?.role || 'user';
    avatarLarge.textContent = username.charAt(0).toUpperCase();
    usernameEl.textContent = username;
    roleEl.textContent = role.charAt(0).toUpperCase() + role.slice(1);
  }

  function renderTabs() {
    if (state.viewer?.role !== 'admin') {
      return '';
    }

    const profileActive = state.activeTab === 'profile' ? '#111827' : '#f3f4f6';
    const profileColor = state.activeTab === 'profile' ? '#ffffff' : '#374151';
    const usersActive = state.activeTab === 'users' ? '#111827' : '#f3f4f6';
    const usersColor = state.activeTab === 'users' ? '#ffffff' : '#374151';

    return `
      <div style="display:flex; gap:0.5rem; margin-bottom:1.25rem;">
        <button type="button" id="accountTabProfile" style="flex:1; border:none; border-radius:10px; padding:0.75rem 1rem; font-weight:600; background:${profileActive}; color:${profileColor};">My Profile</button>
        <button type="button" id="accountTabUsers" style="flex:1; border:none; border-radius:10px; padding:0.75rem 1rem; font-weight:600; background:${usersActive}; color:${usersColor};">User Management</button>
      </div>
    `;
  }

  function renderProfilePanel() {
    const user = state.viewer || {};
    const email = escapeHtml(user.email || '');
    const department = escapeHtml(user.department || '');
    const username = escapeHtml(user.username || '');
    const role = escapeHtml((user.role || 'user').toUpperCase());

    return `
      <div style="display:grid; gap:1rem;">
        <div style="display:grid; gap:0.75rem; grid-template-columns:repeat(2, minmax(0, 1fr));">
          <div style="background:#f9fafb; border:1px solid #e5e7eb; border-radius:12px; padding:0.9rem;">
            <div style="font-size:0.75rem; color:#6b7280; text-transform:uppercase; font-weight:600; margin-bottom:0.35rem;">Username</div>
            <div style="font-weight:600; color:#111827;">${username}</div>
          </div>
          <div style="background:#f9fafb; border:1px solid #e5e7eb; border-radius:12px; padding:0.9rem;">
            <div style="font-size:0.75rem; color:#6b7280; text-transform:uppercase; font-weight:600; margin-bottom:0.35rem;">Role</div>
            <div style="font-weight:600; color:#111827;">${role}</div>
          </div>
        </div>
        <form id="selfProfileForm" style="display:grid; gap:0.9rem;">
          <div>
            <label class="profile-label">Email</label>
            <input type="email" id="selfEmail" class="profile-input" value="${email}" required>
          </div>
          <div>
            <label class="profile-label">Department</label>
            <input type="text" id="selfDepartment" class="profile-input" value="${department}">
          </div>
          <div>
            <label class="profile-label">New Password</label>
            <input type="password" id="selfPassword" class="profile-input" placeholder="Leave blank to keep current password">
          </div>
          <div>
            <label class="profile-label">Confirm Password</label>
            <input type="password" id="selfConfirmPassword" class="profile-input" placeholder="Confirm new password">
          </div>
          <div id="selfProfileMessage" style="display:none; padding:0.75rem; border-radius:10px; font-size:0.9rem;"></div>
          <div style="display:flex; gap:0.75rem;">
            <button type="submit" class="profile-btn profile-btn-save">Save Profile</button>
            <button type="button" id="profileCloseBtn" class="profile-btn profile-btn-close">Close</button>
          </div>
        </form>
      </div>
    `;
  }

  function renderUsersPanel() {
    const selected = getSelectedUser();
    const userButtons = state.users.map((user) => {
      const active = user.id === state.selectedUserId;
      return `
        <button type="button" class="managed-user-btn" data-user-id="${user.id}" style="width:100%; text-align:left; border:1px solid ${active ? '#111827' : '#e5e7eb'}; background:${active ? '#111827' : '#ffffff'}; color:${active ? '#ffffff' : '#111827'}; border-radius:10px; padding:0.8rem 0.9rem; margin-bottom:0.5rem;">
          <div style="font-weight:600;">${escapeHtml(user.username)}</div>
          <div style="font-size:0.8rem; opacity:0.8;">${escapeHtml(user.role || 'user')} | ${escapeHtml(user.email || '')}</div>
        </button>
      `;
    }).join('');

    const selectedMarkup = selected ? `
      <form id="adminUserForm" style="display:grid; gap:0.9rem;">
        <div>
          <label class="profile-label">Username</label>
          <input type="text" id="adminUsername" class="profile-input" value="${escapeHtml(selected.username || '')}" required>
        </div>
        <div>
          <label class="profile-label">Email</label>
          <input type="email" id="adminEmail" class="profile-input" value="${escapeHtml(selected.email || '')}" required>
        </div>
        <div>
          <label class="profile-label">Department</label>
          <input type="text" id="adminDepartment" class="profile-input" value="${escapeHtml(selected.department || '')}">
        </div>
        <div>
          <label class="profile-label">Role</label>
          <select id="adminRole" class="profile-input">
            ${['admin', 'user', 'guest'].map((role) => `<option value="${role}" ${selected.role === role ? 'selected' : ''}>${role.toUpperCase()}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="profile-label">Reset Password</label>
          <input type="password" id="adminPassword" class="profile-input" placeholder="Leave blank to keep current password">
        </div>
        <div>
          <label class="profile-label">Confirm Password</label>
          <input type="password" id="adminConfirmPassword" class="profile-input" placeholder="Confirm new password">
        </div>
        <div id="adminUserMessage" style="display:none; padding:0.75rem; border-radius:10px; font-size:0.9rem;"></div>
        <div style="display:flex; gap:0.75rem;">
          <button type="submit" class="profile-btn profile-btn-save">Save User</button>
          <button type="button" id="refreshUsersBtn" class="profile-btn profile-btn-cancel">Refresh</button>
          <button type="button" id="profileCloseBtn" class="profile-btn profile-btn-close">Close</button>
        </div>
      </form>
    ` : '<div style="padding:1rem; border:1px dashed #d1d5db; border-radius:12px; color:#6b7280;">No users available.</div>';

    return `
      <div style="display:grid; grid-template-columns:220px 1fr; gap:1rem; align-items:start;">
        <div style="max-height:360px; overflow:auto; padding-right:0.25rem;">
          ${userButtons || '<div style="color:#6b7280;">No users found.</div>'}
        </div>
        <div>${selectedMarkup}</div>
      </div>
    `;
  }

  function renderContent() {
    renderHeader();
    content.innerHTML = `
      ${renderTabs()}
      ${state.activeTab === 'users' ? renderUsersPanel() : renderProfilePanel()}
    `;
    bindModalEvents();
  }

  function setMessage(elementId, message, type) {
    const element = document.getElementById(elementId);
    if (!element) {
      return;
    }

    element.textContent = message;
    element.style.display = 'block';
    element.style.background = type === 'error' ? '#fee2e2' : '#dcfce7';
    element.style.color = type === 'error' ? '#991b1b' : '#166534';
    element.style.borderLeft = `4px solid ${type === 'error' ? '#dc2626' : '#10b981'}`;
  }

  async function saveSelfProfile(event) {
    event.preventDefault();

    const email = document.getElementById('selfEmail').value.trim();
    const department = document.getElementById('selfDepartment').value.trim();
    const password = document.getElementById('selfPassword').value;
    const confirmPassword = document.getElementById('selfConfirmPassword').value;

    if (!email) {
      setMessage('selfProfileMessage', 'Email is required', 'error');
      return;
    }

    if (password && password !== confirmPassword) {
      setMessage('selfProfileMessage', 'Passwords do not match', 'error');
      return;
    }

    if (password && password.length < 8) {
      setMessage('selfProfileMessage', 'Password must be at least 8 characters', 'error');
      return;
    }

    try {
      const token = await getCsrfToken();
      const payload = { email, department, confirmPassword };
      if (password) {
        payload.password = password;
      }

      const result = await fetchJson('/api/user/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'csrf-token': token
        },
        body: JSON.stringify(payload)
      });

      state.viewer = result.user;
      syncNavbarIndicator();
      setMessage('selfProfileMessage', 'Profile updated successfully', 'success');
      renderHeader();
    } catch (error) {
      setMessage('selfProfileMessage', error.message, 'error');
    }
  }

  async function saveManagedUser(event) {
    event.preventDefault();
    const selected = getSelectedUser();
    if (!selected) {
      return;
    }

    const username = document.getElementById('adminUsername').value.trim();
    const email = document.getElementById('adminEmail').value.trim();
    const department = document.getElementById('adminDepartment').value.trim();
    const role = document.getElementById('adminRole').value;
    const password = document.getElementById('adminPassword').value;
    const confirmPassword = document.getElementById('adminConfirmPassword').value;

    if (!username) {
      setMessage('adminUserMessage', 'Username is required', 'error');
      return;
    }

    if (!email) {
      setMessage('adminUserMessage', 'Email is required', 'error');
      return;
    }

    if (password && password !== confirmPassword) {
      setMessage('adminUserMessage', 'Passwords do not match', 'error');
      return;
    }

    if (password && password.length < 8) {
      setMessage('adminUserMessage', 'Password must be at least 8 characters', 'error');
      return;
    }

    try {
      const token = await getCsrfToken();
      const payload = { username, email, department, role, confirmPassword };
      if (password) {
        payload.password = password;
      }

      const result = await fetchJson(`/api/users/${selected.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'csrf-token': token
        },
        body: JSON.stringify(payload)
      });

      state.users = state.users.map((user) => user.id === result.user.id ? result.user : user);
      if (state.viewer && state.viewer.id === result.user.id) {
        state.viewer = result.user;
        syncNavbarIndicator();
        renderHeader();
      }
      setMessage('adminUserMessage', 'User updated successfully', 'success');
      renderContent();
    } catch (error) {
      setMessage('adminUserMessage', error.message, 'error');
    }
  }

  async function openProfileModal() {
    if (!state.viewer) {
      return;
    }

    if (state.viewer.role === 'admin' && state.users.length === 0) {
      try {
        await loadUsers();
      } catch (error) {
        console.error('Failed to load users:', error);
      }
    }

    renderContent();
    overlay.classList.add('active');
  }

  function closeProfileModal() {
    overlay.classList.remove('active');
  }

  async function refreshUsersAndRender() {
    try {
      await loadUsers();
      renderContent();
    } catch (error) {
      setMessage('adminUserMessage', error.message, 'error');
    }
  }

  function bindModalEvents() {
    const closeBtn = document.getElementById('profileCloseBtn');
    if (closeBtn) {
      closeBtn.addEventListener('click', closeProfileModal);
    }

    const selfForm = document.getElementById('selfProfileForm');
    if (selfForm) {
      selfForm.addEventListener('submit', saveSelfProfile);
    }

    const tabProfile = document.getElementById('accountTabProfile');
    if (tabProfile) {
      tabProfile.addEventListener('click', () => {
        state.activeTab = 'profile';
        renderContent();
      });
    }

    const tabUsers = document.getElementById('accountTabUsers');
    if (tabUsers) {
      tabUsers.addEventListener('click', async () => {
        state.activeTab = 'users';
        if (state.users.length === 0) {
          await loadUsers();
        }
        renderContent();
      });
    }

    document.querySelectorAll('.managed-user-btn').forEach((button) => {
      button.addEventListener('click', () => {
        state.selectedUserId = Number.parseInt(button.dataset.userId, 10);
        renderContent();
      });
    });

    const adminForm = document.getElementById('adminUserForm');
    if (adminForm) {
      adminForm.addEventListener('submit', saveManagedUser);
    }

    const refreshBtn = document.getElementById('refreshUsersBtn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', refreshUsersAndRender);
    }
  }

  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) {
      closeProfileModal();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && overlay.classList.contains('active')) {
      closeProfileModal();
    }
  });

  window.openProfileModal = openProfileModal;
  window.closeProfileModal = closeProfileModal;

  window.addEventListener('load', () => {
    setTimeout(() => {
      loadViewer().catch((error) => console.error('Account panel init failed:', error));
    }, 0);
  });
})();
