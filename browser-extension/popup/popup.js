let currentState = null;

function formatTime(iso) {
  if (!iso) return 'Never';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return iso;
  }
}

function renderState(res) {
  currentState = res;
  const pill = document.getElementById('connectionPill');
  const browserInfo = document.getElementById('browserInfo');
  const profileIdEl = document.getElementById('profileId');
  const osUserEl = document.getElementById('osUser');
  const osSidEl = document.getElementById('osSid');
  const deviceHostEl = document.getElementById('deviceHost');
  const profileInput = document.getElementById('profileLabelInput');
  const enrollBtn = document.getElementById('enrollBtn');
  const navCountEl = document.getElementById('navCount');
  const dlCountEl = document.getElementById('dlCount');
  const queueDepthEl = document.getElementById('queueDepth');
  const lastDeliveryEl = document.getElementById('lastDelivery');
  const errorBanner = document.getElementById('errorBanner');
  const pauseBtn = document.getElementById('pauseBtn');

  if (!res || !res.ok) {
    pill.textContent = 'Offline';
    pill.className = 'status-pill offline';
    errorBanner.textContent = (res && res.error) || 'Unable to query service worker.';
    errorBanner.classList.remove('hidden');
    return;
  }

  const meta = res.browser_meta || {};
  browserInfo.textContent = `${meta.browser_name || 'Browser'} ${meta.browser_version || ''} • v${meta.extension_version || '2.0.0'}`;
  profileIdEl.textContent = res.profile_id || '—';

  const stats = res.stats || {};
  const host = res.host_status || {};
  const nativeConnected = Boolean(host.ok || stats.native_connected);

  osUserEl.textContent = host.os_user || stats.os_user || 'Not bound';
  osSidEl.textContent = host.os_sid || stats.os_sid || 'Not bound';
  deviceHostEl.textContent = host.device_hostname || stats.device_hostname || '—';

  if (profileInput && !profileInput.value && res.profile_label) {
    profileInput.value = res.profile_label;
  }

  enrollBtn.textContent = res.enrolled ? 'Re-Enroll' : 'Enroll';

  navCountEl.textContent = String(stats.navigations_captured || 0);
  dlCountEl.textContent = String(stats.downloads_tracked || 0);
  const totalQueued = (res.extension_queue_depth || 0) + (host.queue_depth || stats.native_queue_depth || 0);
  queueDepthEl.textContent = String(totalQueued);
  lastDeliveryEl.textContent = formatTime(host.delivered_at || stats.last_delivery_at);

  if (!nativeConnected) {
    pill.textContent = 'Host Offline';
    pill.className = 'status-pill offline';
  } else if (!res.enrolled) {
    pill.textContent = 'Unenrolled';
    pill.className = 'status-pill paused';
  } else if (res.paused) {
    pill.textContent = 'Paused';
    pill.className = 'status-pill paused';
  } else {
    pill.textContent = 'Collecting';
    pill.className = 'status-pill active';
  }

  pauseBtn.textContent = res.paused ? 'Resume Collection' : 'Pause Collection';

  const errText = (!nativeConnected && (host.error || stats.last_error)) || null;
  if (errText) {
    errorBanner.textContent = `Native Host: ${errText}`;
    errorBanner.classList.remove('hidden');
  } else {
    errorBanner.classList.add('hidden');
  }
}

async function refreshPopup() {
  const res = await chrome.runtime.sendMessage({ type: 'GET_POPUP_STATE' });
  renderState(res);
}

document.addEventListener('DOMContentLoaded', async () => {
  await refreshPopup();

  document.getElementById('enrollBtn').addEventListener('click', async () => {
    const label = document.getElementById('profileLabelInput').value.trim();
    const btn = document.getElementById('enrollBtn');
    btn.disabled = true;
    btn.textContent = 'Enrolling...';
    await chrome.runtime.sendMessage({ type: 'ENROLL_PROFILE', profile_label: label });
    btn.disabled = false;
    await refreshPopup();
  });

  document.getElementById('pauseBtn').addEventListener('click', async () => {
    const nextPaused = !(currentState && currentState.paused);
    await chrome.runtime.sendMessage({
      type: 'TOGGLE_PAUSE',
      paused: nextPaused,
      reason: nextPaused ? 'Paused via extension popup' : 'Resumed via extension popup'
    });
    await refreshPopup();
  });

  document.getElementById('flushBtn').addEventListener('click', async () => {
    const btn = document.getElementById('flushBtn');
    btn.disabled = true;
    btn.textContent = 'Syncing...';
    await chrome.runtime.sendMessage({ type: 'FLUSH_NOW' });
    btn.disabled = false;
    btn.textContent = 'Sync Now';
    await refreshPopup();
  });
});
