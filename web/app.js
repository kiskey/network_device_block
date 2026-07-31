// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// State & API Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

let currentView = 'dashboard';
let authStatus = { auth_enabled: false, password_set: false, authenticated: false };

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

async function api(method, path, body) {
    const headers = { 'Content-Type': 'application/json' };
    const csrf = getCookie('csrf_token');
    if (csrf) headers['X-CSRF-Token'] = csrf;

    const res = await fetch(path, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined
    });

    if (res.status === 401) {
        showAuthView();
        throw new Error('Unauthorized');
    }
    
    if (!res.ok) {
        const errData = await res.json().catch(() => ({ error: 'Request failed' }));
        throw new Error(errData.error || 'Request failed');
    }
    
    return res.status === 204 ? null : res.json();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Auth Logic
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function checkAuth() {
    try {
        authStatus = await api('GET', '/api/auth/status');
    } catch (e) {
        authStatus = { auth_enabled: true, authenticated: false };
    }

    if (authStatus.auth_enabled && !authStatus.authenticated) {
        showAuthView();
    } else {
        showAppView();
    }
}

function showAuthView() {
    document.getElementById('auth-view').classList.remove('hidden');
    document.getElementById('app-view').classList.add('hidden');
    
    if (!authStatus.password_set) {
        document.getElementById('auth-subtitle').textContent = 'Welcome! Create a password to secure your gateway.';
        document.getElementById('login-btn').textContent = 'Set Password & Unlock';
    } else {
        document.getElementById('auth-subtitle').textContent = 'Enter your password to manage network access.';
        document.getElementById('login-btn').textContent = 'Unlock';
    }
}

function showAppView() {
    document.getElementById('auth-view').classList.add('hidden');
    document.getElementById('app-view').classList.remove('hidden');
    renderView();
}

document.getElementById('login-btn').addEventListener('click', async () => {
    const password = document.getElementById('password-input').value;
    const errEl = document.getElementById('auth-error');
    errEl.classList.add('hidden');
    
    try {
        await api('POST', '/api/login', { password });
        await checkAuth();
    } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
    }
});

document.getElementById('logout-btn').addEventListener('click', async () => {
    try {
        await api('POST', '/api/logout');
        await checkAuth();
    } catch (e) {}
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Routing & Rendering
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

document.querySelectorAll('.seg-item').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.seg-item').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentView = btn.dataset.view;
        renderView();
    });
});

async function renderView() {
    const main = document.getElementById('main-content');
    main.innerHTML = `<div class="loader">Loading...</div>`;
    
    try {
        if (currentView === 'dashboard') await renderDashboard(main);
        else if (currentView === 'devices') await renderDevices(main);
        else if (currentView === 'schedule') await renderSchedule(main);
    } catch (err) {
        main.innerHTML = `<div class="error-text">Error: ${err.message}</div>`;
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Dashboard View
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function renderDashboard(container) {
    const data = await api('GET', '/api/dashboard');
    
    container.innerHTML = `
        <div class="dash-grid">
            <div class="stat-card">
                <div class="stat-label">Gateway</div>
                <div class="stat-value">${data.gateway_status}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">VPN</div>
                <div class="stat-value">${data.vpn_status}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Internet</div>
                <div class="stat-value">${data.internet_status}</div>
            </div>
        </div>
        <div class="dash-grid">
            <div class="stat-card">
                <div class="stat-label">Online</div>
                <div class="stat-value"><span class="status-dot status-online"></span>${data.online_devices}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Blocked</div>
                <div class="stat-value"><span class="status-dot status-blocked"></span>${data.blocked_devices}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Discovered</div>
                <div class="stat-value">${data.device_count}</div>
            </div>
        </div>
        
        <div class="list-header">Next Scheduled Event</div>
        <div class="card-group">
            <div class="card-item">
                <div class="item-info">
                    <div class="item-title">${data.next_schedule ? ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][data.next_schedule.day_of_week] : 'No Schedules'}</div>
                    <div class="item-subtitle">${data.next_schedule ? `${data.next_schedule.start_time} to ${data.next_schedule.end_time}` : 'Global internet is always on or off'}</div>
                </div>
            </div>
        </div>
    `;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Devices View (Inset Grouped List)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function renderDevices(container) {
    const devices = await api('GET', '/api/devices');
    
    let html = `<div class="list-header">Network Devices</div><div class="card-group">`;
    
    if (devices.length === 0) {
        html += `<div class="card-item"><div class="item-info"><div class="item-title">No devices discovered</div></div></div>`;
    } else {
        devices.forEach(d => {
            const isBlocked = d.policy && d.policy.mode === 'BLOCK_ALWAYS';
            const dotClass = d.online ? 'status-online' : 'status-offline';
            
            html += `
                <div class="card-item" onclick="openDeviceModal('${d.mac}')">
                    <div class="item-info">
                        <div class="item-title">
                            <span class="status-dot ${dotClass}" style="margin-right:8px; display:inline-block;"></span>
                            ${d.friendly_name || d.hostname || 'Unknown Device'}
                        </div>
                        <div class="item-subtitle">
                            ${d.hostname !== d.friendly_name && d.hostname ? d.hostname + ' · ' : ''}
                            ${d.current_ip || 'No IP'}
                        </div>
                    </div>
                    <div class="toggle-switch" onclick="event.stopPropagation()">
                        <input type="checkbox" id="toggle-${d.mac}" ${!isBlocked ? 'checked' : ''} onchange="toggleDevice('${d.mac}', this.checked)">
                        <span class="slider"></span>
                    </div>
                    <div class="item-chevron">›</div>
                </div>
            `;
        });
    }
    
    html += `</div>`;
    container.innerHTML = html;
}

async function toggleDevice(mac, allow) {
    try {
        await api('POST', `/api/devices/${mac}/toggle`);
        // State updated. The toggle already moved visually.
    } catch (err) {
        alert('Failed to toggle device: ' + err.message);
        await renderView();
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Device Modal (Bottom Sheet)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function openDeviceModal(mac) {
    const modal = document.getElementById('modal-overlay');
    const content = document.getElementById('modal-content');
    modal.classList.remove('hidden');
    content.innerHTML = `<div class="loader">Loading...</div>`;

    // Force animation restart
    const card = document.querySelector('.sheet-card');
    card.style.animation = 'none';
    card.offsetHeight; /* trigger reflow */
    card.style.animation = '';

    try {
        const dev = await api('GET', `/api/devices/${mac}`);
        const policy = dev.policy || { mode: 'GLOBAL', enabled: true };
        
        content.innerHTML = `
            <h2>Device Details</h2>
            <div class="form-group">
                <label class="form-label">Friendly Name</label>
                <input type="text" id="dev-friendly" value="${dev.friendly_name || ''}" placeholder="Add a custom name">
            </div>
            <div class="form-group">
                <label class="form-label">MAC Address</label>
                <input type="text" value="${dev.mac}" readonly style="background: var(--fill-tertiary); color: var(--text-secondary);">
            </div>
            <div class="form-group">
                <label class="form-label">Vendor</label>
                <input type="text" value="${dev.vendor || 'Unknown'}" readonly style="background: var(--fill-tertiary); color: var(--text-secondary);">
            </div>
            <div class="form-group">
                <label class="form-label">Policy Mode</label>
                <select id="dev-mode">
                    <option value="GLOBAL" ${policy.mode==='GLOBAL'?'selected':''}>Use Global Policy</option>
                    <option value="ALLOW_ALWAYS" ${policy.mode==='ALLOW_ALWAYS'?'selected':''}>Allow Always</option>
                    <option value="BLOCK_ALWAYS" ${policy.mode==='BLOCK_ALWAYS'?'selected':''}>Block Always</option>
                    <option value="SCHEDULE" ${policy.mode==='SCHEDULE'?'selected':''}>Custom Schedule</option>
                </select>
            </div>
            <button class="btn-primary" onclick="saveDeviceChanges('${dev.mac}')">Save Changes</button>
        `;
    } catch (err) {
        content.innerHTML = `<div class="error-text">${err.message}</div>`;
    }
}

async function saveDeviceChanges(mac) {
    const friendly = document.getElementById('dev-friendly').value;
    const mode = document.getElementById('dev-mode').value;
    
    try {
        if (friendly !== '') await api('PUT', `/api/devices/${mac}`, { friendly_name: friendly });
        await api('PUT', `/api/policies/${mac}`, { mode: mode, enabled: true });
        closeModal();
        await renderView();
    } catch (err) {
        alert('Save failed: ' + err.message);
    }
}

function closeModal() {
    document.getElementById('modal-overlay').classList.add('hidden');
}

// Close modal if clicking outside the sheet
document.getElementById('modal-overlay').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Schedule View (Global)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function renderSchedule(container) {
    const policy = await api('GET', '/api/policies/global');
    const schedules = await api('GET', '/api/schedules/global');
    
    container.innerHTML = `
        <div class="list-header">Global Internet Policy</div>
        <div class="card-group">
            <div class="card-item" style="cursor: default;">
                <div class="item-info"><div class="item-title">Default Mode</div></div>
                <select id="global-mode" style="width: auto; margin-bottom: 0; border: none; background: transparent; color: var(--accent-blue); font-weight: 500;">
                    <option value="ALLOW_ALWAYS" ${policy.mode==='ALLOW_ALWAYS'?'selected':''}>Allow Always</option>
                    <option value="BLOCK_ALWAYS" ${policy.mode==='BLOCK_ALWAYS'?'selected':''}>Block Always</option>
                    <option value="SCHEDULE" ${policy.mode==='SCHEDULE'?'selected':''}>Scheduled</option>
                </select>
            </div>
        </div>
        <button class="btn-secondary" style="margin-bottom: 32px;" onclick="saveGlobalMode()">Update Global Mode</button>
        
        <div class="list-header">Weekly Schedule</div>
        <p style="padding: 0 20px 12px; font-size: 13px;">If mode is set to "Scheduled", devices will be allowed during these times and blocked otherwise. Supports cross-midnight.</p>
        <div class="card-group" style="padding: 16px;">
            <div id="schedules-list"></div>
            <button class="add-schedule-btn" onclick="addScheduleRow()">+ Add Time Range</button>
        </div>
        <button class="btn-primary" style="margin-top: 24px;" onclick="saveSchedules()">Save Schedule</button>
    `;
    
    const list = document.getElementById('schedules-list');
    if (schedules.length === 0) {
        addScheduleRow(); 
    } else {
        schedules.forEach(s => addScheduleRow(s));
    }
}

function addScheduleRow(s = null) {
    const list = document.getElementById('schedules-list');
    const div = document.createElement('div');
    div.className = 'schedule-row';
    div.innerHTML = `
        <select class="sched-day">
            ${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map((d,i) => 
                `<option value="${i}" ${s && s.day_of_week===i?'selected':''}>${d}</option>`
            ).join('')}
        </select>
        <input type="time" class="sched-start" value="${s ? s.start_time : '08:00'}">
        <input type="time" class="sched-end" value="${s ? s.end_time : '17:00'}">
        <button class="btn-secondary" onclick="this.parentNode.remove()" style="padding: 8px 12px;">✕</button>
    `;
    list.appendChild(div);
}

async function saveGlobalMode() {
    const mode = document.getElementById('global-mode').value;
    try {
        await api('PUT', '/api/policies/global', { mode: mode, enabled: true });
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

async function saveSchedules() {
    const rows = document.querySelectorAll('.schedule-row');
    
    try {
        // Clear existing global schedules
        const existing = await api('GET', '/api/schedules/global');
        for (const s of existing) {
            await api('DELETE', `/api/schedules/${s.id}`);
        }
        
        // Add new ones
        for (const row of rows) {
            const day = row.querySelector('.sched-day').value;
            const start = row.querySelector('.sched-start').value;
            const end = row.querySelector('.sched-end').value;
            
            if (start && end) {
                await api('POST', '/api/schedules/global', {
                    day_of_week: parseInt(day),
                    start_time: start,
                    end_time: end,
                    enabled: true
                });
            }
        }
        await renderView();
    } catch (err) {
        alert('Failed to save schedule: ' + err.message);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Init
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
document.addEventListener('DOMContentLoaded', checkAuth);
