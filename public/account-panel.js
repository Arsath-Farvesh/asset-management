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
    selectedUserId: null,
    wizardStep: 0,       // 0 = not open, 1-3 = wizard steps
    wizardData: {}
  };

  const MAX_AVATAR_FILE_SIZE = 350 * 1024;

  function getAvatarSource(user) {
    const source = user?.avatar_url || user?.avatar || '';
    return String(source || '').trim();
  }

  function applyAvatar(element, user, fallbackText) {
    if (!element) {
      return;
    }

    const source = getAvatarSource(user);
    if (source) {
      const safeSource = source.replace(/"/g, '%22');
      element.textContent = '';
      element.style.backgroundImage = `url("${safeSource}")`;
      element.style.backgroundSize = 'cover';
      element.style.backgroundPosition = 'center';
      element.style.backgroundRepeat = 'no-repeat';
      element.style.color = 'transparent';
    } else {
      element.textContent = fallbackText;
      element.style.backgroundImage = '';
      element.style.backgroundSize = '';
      element.style.backgroundPosition = '';
      element.style.backgroundRepeat = '';
      element.style.color = '';
    }
  }

  function renderAvatarField(prefix, user) {
    const fallback = (user?.username || 'U').charAt(0).toUpperCase();
    const avatarUrl = escapeHtml(getAvatarSource(user));
    return `
      <div style="display:grid; gap:0.75rem; padding:0.9rem; border:1px solid #e5e7eb; border-radius:12px; background:#f9fafb;">
        <div style="display:flex; align-items:center; gap:0.9rem;">
          <div id="${prefix}AvatarPreview" class="profile-avatar-large" style="width:64px; height:64px; margin:0; font-size:1.35rem;">${fallback}</div>
          <div>
            <div style="font-weight:600; color:#111827; margin-bottom:0.2rem;">Profile Photo</div>
            <div style="font-size:0.85rem; color:#6b7280;">Upload a JPG, PNG, or WebP image up to 350 KB, or paste an image URL.</div>
          </div>
        </div>
        <div>
          <label class="profile-label">Photo URL</label>
          <input type="url" id="${prefix}AvatarUrl" class="profile-input" value="${avatarUrl}" placeholder="https://example.com/photo.jpg or leave blank">
        </div>
        <div>
          <label class="profile-label">Upload Photo</label>
          <input type="file" id="${prefix}AvatarFile" class="profile-input" accept="image/png,image/jpeg,image/webp,image/gif">
        </div>
      </div>
    `;
  }

  function getPreviewUser(prefix, fallbackUser) {
    const previewUser = { ...fallbackUser };
    const avatarInput = document.getElementById(`${prefix}AvatarUrl`);
    previewUser.avatar_url = avatarInput ? avatarInput.value.trim() : getAvatarSource(fallbackUser);
    return previewUser;
  }

  function refreshAvatarPreview(prefix, fallbackUser) {
    const preview = document.getElementById(`${prefix}AvatarPreview`);
    if (!preview) {
      return;
    }

    const previewUser = getPreviewUser(prefix, fallbackUser);
    const fallback = (fallbackUser?.username || 'U').charAt(0).toUpperCase();
    applyAvatar(preview, previewUser, fallback);
  }

  function bindAvatarField(prefix, fallbackUser, messageElementId) {
    const urlInput = document.getElementById(`${prefix}AvatarUrl`);
    const fileInput = document.getElementById(`${prefix}AvatarFile`);

    refreshAvatarPreview(prefix, fallbackUser);

    if (urlInput) {
      urlInput.addEventListener('input', () => {
        refreshAvatarPreview(prefix, fallbackUser);
      });
    }

    if (fileInput) {
      fileInput.addEventListener('change', () => {
        const file = fileInput.files && fileInput.files[0];
        if (!file) {
          return;
        }

        if (!file.type.startsWith('image/')) {
          setMessage(messageElementId, 'Please choose an image file', 'error');
          fileInput.value = '';
          return;
        }

        if (file.size > MAX_AVATAR_FILE_SIZE) {
          setMessage(messageElementId, 'Profile photo must be 350 KB or smaller', 'error');
          fileInput.value = '';
          return;
        }

        const reader = new FileReader();
        reader.onload = () => {
          if (urlInput) {
            urlInput.value = String(reader.result || '');
          }
          refreshAvatarPreview(prefix, fallbackUser);
        };
        reader.onerror = () => {
          setMessage(messageElementId, 'Failed to read the selected photo', 'error');
        };
        reader.readAsDataURL(file);
      });
    }
  }

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
      applyAvatar(userAvatar, state.viewer, state.viewer.username.charAt(0).toUpperCase());
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

    // Hide add-asset form on index page for non-admin users
    const addAssetHeader = document.getElementById('addAssetHeader');
    const addAssetMain   = document.getElementById('addAssetMain');
    const addAssetNoAccess = document.getElementById('addAssetNoAccess');
    if (addAssetHeader && addAssetMain) {
      const isAdmin = state.viewer?.role === 'admin';
      addAssetHeader.style.display  = isAdmin ? '' : 'none';
      addAssetMain.style.display    = isAdmin ? '' : 'none';
      if (addAssetNoAccess) addAssetNoAccess.style.display = isAdmin ? 'none' : '';
    }
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
    applyAvatar(avatarLarge, state.viewer, username.charAt(0).toUpperCase());
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
    const firstName = escapeHtml(user.first_name || '');
    const lastName = escapeHtml(user.last_name || '');
    const officeLocation = escapeHtml(user.office_location || '');
    const phone = escapeHtml(user.phone || '');

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
          ${renderAvatarField('self', user)}
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
            <div>
              <label class="profile-label">First Name</label>
              <input type="text" id="selfFirstName" class="profile-input" value="${firstName}">
            </div>
            <div>
              <label class="profile-label">Last Name</label>
              <input type="text" id="selfLastName" class="profile-input" value="${lastName}">
            </div>
          </div>
          <div>
            <label class="profile-label">Email</label>
            <input type="email" id="selfEmail" class="profile-input" value="${email}" required>
          </div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
            <div>
              <label class="profile-label">Department</label>
              <input type="text" id="selfDepartment" class="profile-input" value="${department}">
            </div>
            <div>
              <label class="profile-label">Office Location</label>
              <input type="text" id="selfOfficeLocation" class="profile-input" value="${officeLocation}">
            </div>
          </div>
          <div>
            <label class="profile-label">Phone</label>
            <input type="text" id="selfPhone" class="profile-input" value="${phone}">
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
    // Show wizard inline if active
    if (state.wizardStep > 0) {
      return renderWizard();
    }

    const selected = getSelectedUser();
    const userButtons = state.users.map((user) => {
      const active = user.id === state.selectedUserId;
      const initials = (user.first_name ? user.first_name.charAt(0) : user.username.charAt(0)).toUpperCase();
      const displayName = user.first_name
        ? `${escapeHtml(user.first_name)} ${escapeHtml(user.last_name || '')}`
        : escapeHtml(user.username);
      const avatarUrl = getAvatarSource(user);
      const avatarStyle = avatarUrl
        ? `background-image:url('${escapeHtml(avatarUrl)}'); background-size:cover; background-position:center; background-repeat:no-repeat; color:transparent;`
        : `background:${active ? 'rgba(255,255,255,0.2)' : '#f3f4f6'};`;
      return `
        <button type="button" class="managed-user-btn" data-user-id="${user.id}" style="width:100%; text-align:left; border:1px solid ${active ? 'var(--brand-500)' : '#e5e7eb'}; background:${active ? '#111827' : '#ffffff'}; color:${active ? '#ffffff' : '#111827'}; border-radius:10px; padding:0.75rem 0.9rem; margin-bottom:0.5rem; display:flex; align-items:center; gap:0.6rem;">
          <div style="width:32px; height:32px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:0.85rem; flex-shrink:0; ${avatarStyle}">${initials}</div>
          <div>
            <div style="font-weight:600; font-size:0.9rem;">${displayName}</div>
            <div style="font-size:0.75rem; opacity:0.75;">${escapeHtml(user.role || 'user')} &bull; ${escapeHtml(user.email || '')}</div>
          </div>
        </button>
      `;
    }).join('');

    const selectedMarkup = selected ? `
      <form id="adminUserForm" style="display:grid; gap:0.9rem;">
        ${renderAvatarField('admin', selected)}
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
          <div>
            <label class="profile-label">First Name</label>
            <input type="text" id="adminFirstName" class="profile-input" value="${escapeHtml(selected.first_name || '')}" placeholder="First name">
          </div>
          <div>
            <label class="profile-label">Last Name</label>
            <input type="text" id="adminLastName" class="profile-input" value="${escapeHtml(selected.last_name || '')}" placeholder="Last name">
          </div>
        </div>
        <div>
          <label class="profile-label">Username</label>
          <input type="text" id="adminUsername" class="profile-input" value="${escapeHtml(selected.username || '')}" required>
        </div>
        <div>
          <label class="profile-label">Email</label>
          <input type="email" id="adminEmail" class="profile-input" value="${escapeHtml(selected.email || '')}" required>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
          <div>
            <label class="profile-label">Department</label>
            <input type="text" id="adminDepartment" class="profile-input" value="${escapeHtml(selected.department || '')}">
          </div>
          <div>
            <label class="profile-label">Office Location</label>
            <input type="text" id="adminOffice" class="profile-input" value="${escapeHtml(selected.office_location || '')}">
          </div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
          <div>
            <label class="profile-label">Phone</label>
            <input type="text" id="adminPhone" class="profile-input" value="${escapeHtml(selected.phone || '')}">
          </div>
          <div>
            <label class="profile-label">Role</label>
            <select id="adminRole" class="profile-input">
              ${['admin', 'user', 'guest'].map((role) => `<option value="${role}" ${selected.role === role ? 'selected' : ''}>${role.toUpperCase()}</option>`).join('')}
            </select>
          </div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
          <div>
            <label class="profile-label">Reset Password</label>
            <input type="password" id="adminPassword" class="profile-input" placeholder="Leave blank to keep current">
          </div>
          <div>
            <label class="profile-label">Confirm Password</label>
            <input type="password" id="adminConfirmPassword" class="profile-input" placeholder="Confirm new password">
          </div>
        </div>
        <div id="adminUserMessage" style="display:none; padding:0.75rem; border-radius:10px; font-size:0.9rem;"></div>
        <div style="display:flex; gap:0.75rem;">
          <button type="submit" class="profile-btn profile-btn-save">Save User</button>
          <button type="button" id="refreshUsersBtn" class="profile-btn profile-btn-cancel">Refresh</button>
          <button type="button" id="profileCloseBtn" class="profile-btn profile-btn-close">Close</button>
        </div>
      </form>
    ` : '<div style="padding:1rem; border:1px dashed #d1d5db; border-radius:12px; color:#6b7280;">Select a user from the list.</div>';

    return `
      <div style="display:grid; grid-template-columns:240px 1fr; gap:1rem; align-items:start;">
        <div>
          <button type="button" id="addUserBtn" style="width:100%; display:flex; align-items:center; justify-content:center; gap:0.4rem; border:2px dashed var(--brand-500); background:transparent; color:var(--brand-500); border-radius:10px; padding:0.65rem 0.9rem; margin-bottom:0.75rem; font-weight:600; cursor:pointer; font-size:0.9rem;">
            <span style="font-size:1.1rem;">+</span> Add User
          </button>
          <div style="max-height:340px; overflow:auto; padding-right:0.25rem;">
            ${userButtons || '<div style="color:#6b7280; font-size:0.9rem;">No users found.</div>'}
          </div>
        </div>
        <div>${selectedMarkup}</div>
      </div>
    `;
  }

  function renderWizard() {
    const step = state.wizardStep;
    const d = state.wizardData;

    const stepLabels = ['Basics', 'Settings', 'Review & Finish'];
    const stepsHtml = stepLabels.map((label, i) => {
      const num = i + 1;
      const active = num === step;
      const done = num < step;
      const bg = done ? '#10b981' : active ? 'var(--brand-500)' : '#e5e7eb';
      const color = done || active ? '#fff' : '#9ca3af';
      return `
        <div style="display:flex; align-items:center; gap:0.4rem;">
          <div style="width:26px; height:26px; border-radius:50%; background:${bg}; color:${color}; display:flex; align-items:center; justify-content:center; font-size:0.75rem; font-weight:700;">${done ? '&#10003;' : num}</div>
          <span style="font-size:0.8rem; font-weight:${active ? '700' : '500'}; color:${active ? '#111827' : '#9ca3af'};">${label}</span>
          ${num < 3 ? '<span style="color:#d1d5db; margin:0 0.25rem;">›</span>' : ''}
        </div>`;
    }).join('');

    let bodyHtml = '';

    if (step === 1) {
      bodyHtml = `
        <div style="display:grid; gap:0.85rem;">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
            <div>
              <label class="profile-label">First Name</label>
              <input type="text" id="wFirstName" class="profile-input" value="${escapeHtml(d.first_name || '')}" placeholder="First name">
            </div>
            <div>
              <label class="profile-label">Last Name</label>
              <input type="text" id="wLastName" class="profile-input" value="${escapeHtml(d.last_name || '')}" placeholder="Last name">
            </div>
          </div>
          <div>
            <label class="profile-label">Display Name / Username <span style="color:var(--brand-500)">*</span></label>
            <input type="text" id="wUsername" class="profile-input" value="${escapeHtml(d.username || '')}" placeholder="e.g. john.doe" required>
          </div>
          <div>
            <label class="profile-label">Email Address <span style="color:var(--brand-500)">*</span></label>
            <input type="email" id="wEmail" class="profile-input" value="${escapeHtml(d.email || '')}" placeholder="user@company.com" required>
          </div>
          <div id="wizardMsg" style="display:none; padding:0.65rem; border-radius:8px; font-size:0.85rem;"></div>
          <div style="display:flex; gap:0.75rem; justify-content:flex-end;">
            <button type="button" id="wizardCancel" class="profile-btn profile-btn-close">Cancel</button>
            <button type="button" id="wizardNext" class="profile-btn profile-btn-save">Next &rsaquo;</button>
          </div>
        </div>`;
    } else if (step === 2) {
      bodyHtml = `
        <div style="display:grid; gap:0.85rem;">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
            <div>
              <label class="profile-label">Role</label>
              <select id="wRole" class="profile-input">
                <option value="user" ${d.role === 'user' ? 'selected' : ''}>USER</option>
                <option value="admin" ${d.role === 'admin' ? 'selected' : ''}>ADMIN</option>
                <option value="guest" ${d.role === 'guest' ? 'selected' : ''}>GUEST</option>
              </select>
            </div>
            <div>
              <label class="profile-label">Department</label>
              <input type="text" id="wDepartment" class="profile-input" value="${escapeHtml(d.department || '')}" placeholder="e.g. IT, HR">
            </div>
          </div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
            <div>
              <label class="profile-label">Office Location</label>
              <input type="text" id="wOffice" class="profile-input" value="${escapeHtml(d.office_location || '')}" placeholder="e.g. Dubai HQ">
            </div>
            <div>
              <label class="profile-label">Phone</label>
              <input type="text" id="wPhone" class="profile-input" value="${escapeHtml(d.phone || '')}" placeholder="+971 ...">
            </div>
          </div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
            <div>
              <label class="profile-label">Password <span style="color:var(--brand-500)">*</span></label>
              <input type="password" id="wPassword" class="profile-input" placeholder="Min 8 characters">
            </div>
            <div>
              <label class="profile-label">Confirm Password <span style="color:var(--brand-500)">*</span></label>
              <input type="password" id="wConfirmPassword" class="profile-input" placeholder="Repeat password">
            </div>
          </div>
          <div id="wizardMsg" style="display:none; padding:0.65rem; border-radius:8px; font-size:0.85rem;"></div>
          <div style="display:flex; gap:0.75rem; justify-content:flex-end;">
            <button type="button" id="wizardBack" class="profile-btn profile-btn-cancel">&lsaquo; Back</button>
            <button type="button" id="wizardNext" class="profile-btn profile-btn-save">Review &rsaquo;</button>
          </div>
        </div>`;
    } else {
      // Step 3 — Review
      const row = (label, val) =>
        `<div style="display:flex; justify-content:space-between; align-items:center; padding:0.5rem 0; border-bottom:1px solid #f3f4f6;">
           <span style="font-size:0.8rem; color:#6b7280; text-transform:uppercase; font-weight:600;">${label}</span>
           <span style="font-weight:600; color:#111827; text-align:right;">${escapeHtml(val || '—')}</span>
         </div>`;
      bodyHtml = `
        <div style="background:#f9fafb; border:1px solid #e5e7eb; border-radius:12px; padding:1rem; margin-bottom:0.9rem;">
          ${row('First name', d.first_name)}
          ${row('Last name', d.last_name)}
          ${row('Username', d.username)}
          ${row('Email', d.email)}
          ${row('Role', (d.role || 'user').toUpperCase())}
          ${row('Department', d.department)}
          ${row('Office Location', d.office_location)}
          ${row('Phone', d.phone)}
          <div style="display:flex; justify-content:space-between; align-items:center; padding:0.5rem 0;">
            <span style="font-size:0.8rem; color:#6b7280; text-transform:uppercase; font-weight:600;">Password</span>
            <span style="font-weight:600; color:#111827;">••••••••</span>
          </div>
        </div>
        <div id="wizardMsg" style="display:none; padding:0.65rem; border-radius:8px; font-size:0.85rem; margin-bottom:0.75rem;"></div>
        <div style="display:flex; gap:0.75rem; justify-content:flex-end;">
          <button type="button" id="wizardBack" class="profile-btn profile-btn-cancel">&lsaquo; Back</button>
          <button type="button" id="wizardFinish" class="profile-btn profile-btn-save">&#10003; Create User</button>
        </div>`;
    }

    return `
      <div>
        <div style="display:flex; align-items:center; gap:0.25rem; margin-bottom:1.25rem; flex-wrap:wrap;">${stepsHtml}</div>
        ${bodyHtml}
      </div>`;
  }

  function renderContent() {
    renderHeader();
    content.innerHTML = `
      ${renderTabs()}
      ${state.activeTab === 'users' ? renderUsersPanel() : renderProfilePanel()}
    `;
    // Widen the modal when showing the two-column admin user management panel
    const modal = overlay.querySelector('.profile-modal');
    if (modal) {
      if (state.activeTab === 'users') {
        modal.classList.add('profile-modal--wide');
      } else {
        modal.classList.remove('profile-modal--wide');
      }
    }
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
    const firstName = document.getElementById('selfFirstName').value.trim();
    const lastName = document.getElementById('selfLastName').value.trim();
    const officeLocation = document.getElementById('selfOfficeLocation').value.trim();
    const phone = document.getElementById('selfPhone').value.trim();
    const avatarUrl = document.getElementById('selfAvatarUrl').value.trim();
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
      const payload = {
        email,
        department,
        confirmPassword,
        first_name: firstName,
        last_name: lastName,
        office_location: officeLocation,
        phone,
        avatar_url: avatarUrl
      };
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
      renderContent();
      setMessage('selfProfileMessage', 'Profile updated successfully', 'success');
    } catch (error) {
      setMessage('selfProfileMessage', error.message, 'error');
    }
  }

  async function saveNewUser() {
    const d = state.wizardData;
    const wizardMsgEl = document.getElementById('wizardMsg');

    function showWizardMsg(msg, type) {
      if (!wizardMsgEl) return;
      wizardMsgEl.textContent = msg;
      wizardMsgEl.style.display = 'block';
      wizardMsgEl.style.background = type === 'error' ? '#fee2e2' : '#dcfce7';
      wizardMsgEl.style.color = type === 'error' ? '#991b1b' : '#166534';
      wizardMsgEl.style.borderLeft = `4px solid ${type === 'error' ? '#dc2626' : '#10b981'}`;
    }

    try {
      const token = await getCsrfToken();
      const result = await fetchJson('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'csrf-token': token },
        body: JSON.stringify(d)
      });

      state.users.push(result.user);
      state.selectedUserId = result.user.id;
      state.wizardStep = 0;
      state.wizardData = {};
      renderContent();
    } catch (error) {
      if (wizardMsgEl) {
        wizardMsgEl.textContent = error.message;
        wizardMsgEl.style.display = 'block';
        wizardMsgEl.style.background = '#fee2e2';
        wizardMsgEl.style.color = '#991b1b';
        wizardMsgEl.style.borderLeft = '4px solid #dc2626';
      }
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
    const firstName = document.getElementById('adminFirstName').value.trim();
    const lastName = document.getElementById('adminLastName').value.trim();
    const officeLocation = document.getElementById('adminOffice').value.trim();
    const phone = document.getElementById('adminPhone').value.trim();
    const avatarUrl = document.getElementById('adminAvatarUrl').value.trim();
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
      const payload = {
        username,
        email,
        department,
        role,
        confirmPassword,
        first_name: firstName,
        last_name: lastName,
        office_location: officeLocation,
        phone,
        avatar_url: avatarUrl
      };
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
      }
      renderContent();
      setMessage('adminUserMessage', 'User updated successfully', 'success');
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
    // Remove any inline display style set by legacy HTML before toggling the CSS class
    overlay.style.removeProperty('display');
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
      bindAvatarField('self', state.viewer, 'selfProfileMessage');
    }

    const tabProfile = document.getElementById('accountTabProfile');
    if (tabProfile) {
      tabProfile.addEventListener('click', () => {
        state.activeTab = 'profile';
        state.wizardStep = 0;
        renderContent();
      });
    }

    const tabUsers = document.getElementById('accountTabUsers');
    if (tabUsers) {
      tabUsers.addEventListener('click', async () => {
        state.activeTab = 'users';
        state.wizardStep = 0;
        if (state.users.length === 0) {
          await loadUsers();
        }
        renderContent();
      });
    }

    // Add User button → start wizard
    const addUserBtn = document.getElementById('addUserBtn');
    if (addUserBtn) {
      addUserBtn.addEventListener('click', () => {
        state.wizardStep = 1;
        state.wizardData = {};
        renderContent();
      });
    }

    // Wizard events (only bound when wizard is active)
    const wizardCancel = document.getElementById('wizardCancel');
    if (wizardCancel) {
      wizardCancel.addEventListener('click', () => {
        state.wizardStep = 0;
        state.wizardData = {};
        renderContent();
      });
    }

    const wizardBack = document.getElementById('wizardBack');
    if (wizardBack) {
      wizardBack.addEventListener('click', () => {
        state.wizardStep = Math.max(1, state.wizardStep - 1);
        renderContent();
      });
    }

    const wizardNext = document.getElementById('wizardNext');
    if (wizardNext) {
      wizardNext.addEventListener('click', () => {
        const d = state.wizardData;
        const msgEl = document.getElementById('wizardMsg');

        function showErr(msg) {
          if (!msgEl) return;
          msgEl.textContent = msg;
          msgEl.style.display = 'block';
          msgEl.style.background = '#fee2e2';
          msgEl.style.color = '#991b1b';
          msgEl.style.borderLeft = '4px solid #dc2626';
        }

        if (state.wizardStep === 1) {
          const username = document.getElementById('wUsername')?.value.trim();
          const email = document.getElementById('wEmail')?.value.trim();
          if (!username) { showErr('Username is required'); return; }
          if (!email) { showErr('Email is required'); return; }
          d.username = username;
          d.email = email;
          d.first_name = document.getElementById('wFirstName')?.value.trim() || '';
          d.last_name = document.getElementById('wLastName')?.value.trim() || '';
        } else if (state.wizardStep === 2) {
          const password = document.getElementById('wPassword')?.value;
          const confirm = document.getElementById('wConfirmPassword')?.value;
          if (!password) { showErr('Password is required'); return; }
          if (password.length < 8) { showErr('Password must be at least 8 characters'); return; }
          if (password !== confirm) { showErr('Passwords do not match'); return; }
          d.role = document.getElementById('wRole')?.value || 'user';
          d.department = document.getElementById('wDepartment')?.value.trim() || '';
          d.office_location = document.getElementById('wOffice')?.value.trim() || '';
          d.phone = document.getElementById('wPhone')?.value.trim() || '';
          d.password = password;
          d.confirmPassword = confirm;
        }

        state.wizardStep += 1;
        renderContent();
      });
    }

    const wizardFinish = document.getElementById('wizardFinish');
    if (wizardFinish) {
      wizardFinish.addEventListener('click', saveNewUser);
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
      bindAvatarField('admin', getSelectedUser(), 'adminUserMessage');
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
