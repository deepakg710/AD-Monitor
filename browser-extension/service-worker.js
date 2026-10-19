/**
 * AD Monitor - Manifest V3 Browser Telemetry Service Worker
 * =========================================================
 * Privacy & Security Guarantees:
 * 1. Top-level frame (frameId === 0) HTTP/HTTPS navigations only.
 * 2. Strips URL path, query string, fragment, credentials, and port before queueing.
 * 3. Never captures page DOM, form inputs, passwords, cookies, or request bodies.
 * 4. Ignores Incognito/InPrivate windows and internal browser schemes (chrome://, edge://, about:, file:).
 * 5. Communicates exclusively with local Windows Native Messaging host (com.admonitor.browser_bridge);
 *    no backend token is ever stored in the browser extension.
 */

const NATIVE_HOST_NAME = 'com.admonitor.browser_bridge';
const DEDUP_WINDOW_MS = 2000;
const MAX_LOCAL_QUEUE = 250;
const ALARM_FLUSH = 'admonitor_flush_alarm';
const ALARM_HEARTBEAT = 'admonitor_heartbeat_alarm';

function detectBrowserMeta() {
  const ua = navigator.userAgent || '';
  let browserName = 'Chromium';
  let browserVersion = 'unknown';
  const edgMatch = ua.match(/Edg\/([\d.]+)/);
  const chrMatch = ua.match(/Chrome\/([\d.]+)/);
  if (edgMatch) {
    browserName = 'Microsoft Edge';
    browserVersion = edgMatch[1];
  } else if (chrMatch) {
    browserName = 'Google Chrome';
    browserVersion = chrMatch[1];
  }
  const manifest = chrome.runtime.getManifest();
  return {
    browser_name: browserName,
    browser_version: browserVersion,
    extension_id: chrome.runtime.id || 'unpacked-extension',
    extension_version: manifest.version || '2.0.0'
  };
}

/**
 * Extracts only the lowercase hostname and scheme (http/https) from a URL string.
 * Returns null for non-HTTP(S) schemes or malformed URLs.
 */
function sanitizeDomainOnly(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    const domain = (parsed.hostname || '').trim().toLowerCase().replace(/\.$/, '');
    if (!domain) return null;
    return {
      domain,
      scheme: parsed.protocol.replace(':', '')
    };
  } catch {
    return null;
  }
}

function extractBasename(filePath) {
  if (!filePath || typeof filePath !== 'string') return '';
  const parts = filePath.split(/[/\\]/);
  return parts[parts.length - 1] || '';
}

async function ensureStateInitialized() {
  const data = await chrome.storage.local.get([
    'profile_id',
    'profile_label',
    'enrolled',
    'paused',
    'pause_reason',
    'pending_queue',
    'download_revisions',
    'nav_dedup',
    'stats'
  ]);

  const updates = {};
  if (!data.profile_id) {
    updates.profile_id = 'bprof-' + crypto.randomUUID();
  }
  if (!data.profile_label) {
    const meta = detectBrowserMeta();
    updates.profile_label = `${meta.browser_name} Default Profile`;
  }
  if (typeof data.enrolled !== 'boolean') {
    updates.enrolled = true;
  }
  if (typeof data.paused !== 'boolean') {
    updates.paused = false;
  }
  if (!Array.isArray(data.pending_queue)) {
    updates.pending_queue = [];
  }
  if (!data.download_revisions || typeof data.download_revisions !== 'object') {
    updates.download_revisions = {};
  }
  if (!data.nav_dedup || typeof data.nav_dedup !== 'object') {
    updates.nav_dedup = {};
  }
  if (!data.stats || typeof data.stats !== 'object') {
    updates.stats = {
      navigations_captured: 0,
      downloads_tracked: 0,
      last_delivery_at: null,
      last_error: null,
      native_connected: false,
      os_user: null,
      os_sid: null,
      device_hostname: null
    };
  }

  if (Object.keys(updates).length > 0) {
    await chrome.storage.local.set(updates);
  }
  return { ...data, ...updates };
}

async function sendToNativeHost(message) {
  try {
    const response = await chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, message);
    const { stats = {} } = await chrome.storage.local.get('stats');
    const updatedStats = {
      ...stats,
      native_connected: Boolean(response && response.ok),
      last_error: response && !response.ok ? (response.error || 'Native host error') : null,
      os_user: (response && response.os_user) || stats.os_user || null,
      os_sid: (response && response.os_sid) || stats.os_sid || null,
      device_hostname: (response && response.device_hostname) || stats.device_hostname || null,
      native_queue_depth: (response && typeof response.queue_depth === 'number') ? response.queue_depth : (stats.native_queue_depth || 0)
    };
    if (response && response.ok && response.delivered_at) {
      updatedStats.last_delivery_at = response.delivered_at;
    }
    if (response && typeof response.enrolled === 'boolean') {
      await chrome.storage.local.set({ enrolled: response.enrolled });
    }
    await chrome.storage.local.set({ stats: updatedStats });
    return response;
  } catch (err) {
    const errMsg = err && err.message ? err.message : String(err);
    const { stats = {} } = await chrome.storage.local.get('stats');
    await chrome.storage.local.set({
      stats: {
        ...stats,
        native_connected: false,
        last_error: errMsg
      }
    });
    return { ok: false, error: errMsg };
  }
}

async function enqueueAndFlushRecord(record) {
  const state = await ensureStateInitialized();
  const queue = Array.isArray(state.pending_queue) ? state.pending_queue : [];
  queue.push(record);
  while (queue.length > MAX_LOCAL_QUEUE) {
    queue.shift();
  }
  await chrome.storage.local.set({ pending_queue: queue });
  await flushPendingQueue();
}

async function flushPendingQueue() {
  const state = await ensureStateInitialized();
  const queue = Array.isArray(state.pending_queue) ? state.pending_queue : [];
  if (queue.length === 0) {
    return { ok: true, flushed: 0 };
  }

  const batch = queue.slice(0, 40);
  const response = await sendToNativeHost({
    action: 'ingest_records',
    profile_id: state.profile_id,
    records: batch
  });

  if (response && response.ok) {
    const ackIds = new Set(Array.isArray(response.acknowledged) ? response.acknowledged : batch.map(r => r.id));
    const current = await chrome.storage.local.get('pending_queue');
    const remaining = (current.pending_queue || []).filter(item => !ackIds.has(item.id));
    await chrome.storage.local.set({ pending_queue: remaining });
    return { ok: true, flushed: ackIds.size, remaining: remaining.length };
  }
  return { ok: false, error: response ? response.error : 'Native host unreachable', remaining: queue.length };
}

// 1. Top-level HTTP/HTTPS Domain Navigation Listener
chrome.webNavigation.onCommitted.addListener(async (details) => {
  try {
    // Strictly top-level frame only
    if (details.frameId !== 0) return;
    if (details.incognito || (chrome.extension && chrome.extension.inIncognitoContext)) return;

    const sanitized = sanitizeDomainOnly(details.url);
    if (!sanitized) return;

    const state = await ensureStateInitialized();
    if (state.paused) return;

    const nowMs = Date.now();
    const dedupKey = `${details.tabId}:${sanitized.domain}`;
    const navDedup = state.nav_dedup || {};
    const lastSeenMs = navDedup[dedupKey] || 0;
    if (nowMs - lastSeenMs < DEDUP_WINDOW_MS) {
      return;
    }

    // Prune old dedup keys (>30s) and store current
    const prunedDedup = {};
    for (const [k, ts] of Object.entries(navDedup)) {
      if (nowMs - ts < 30000) prunedDedup[k] = ts;
    }
    prunedDedup[dedupKey] = nowMs;

    const meta = detectBrowserMeta();
    const navTimeIso = details.timeStamp
      ? new Date(details.timeStamp).toISOString()
      : new Date().toISOString();

    const record = {
      id: 'bnav-' + crypto.randomUUID(),
      kind: 'browser_navigation',
      data: {
        profile_id: state.profile_id,
        browser_name: meta.browser_name,
        browser_version: meta.browser_version,
        extension_id: meta.extension_id,
        extension_version: meta.extension_version,
        navigation_time: navTimeIso,
        domain: sanitized.domain,
        scheme: sanitized.scheme,
        transition_type: details.transitionType || 'link',
        tab_context: 'top_frame',
        frame_id: 0,
        is_incognito: false
      }
    };

    const stats = state.stats || {};
    stats.navigations_captured = (stats.navigations_captured || 0) + 1;
    await chrome.storage.local.set({ nav_dedup: prunedDedup, stats });
    await enqueueAndFlushRecord(record);
  } catch (err) {
    console.error('AD Monitor navigation capture error:', err);
  }
});

async function processDownloadItem(item, triggerSource) {
  if (!item || item.incognito) return;
  const state = await ensureStateInitialized();
  if (state.paused) return;

  const sourceSanitized = sanitizeDomainOnly(item.finalUrl || item.url || '');
  const referrerSanitized = sanitizeDomainOnly(item.referrer || '');
  const dlKey = String(item.id);

  const revisions = state.download_revisions || {};
  const prev = revisions[dlKey] || { revision: 0, last_state: null, filename: '', target_path: '' };
  const currentState = item.state || 'in_progress';
  const currentFilename = extractBasename(item.filename || '') || prev.filename || '';
  const currentTargetPath = item.filename || prev.target_path || '';

  // Avoid duplicate revisions if state and filename haven't changed on periodic events
  if (
    triggerSource === 'changed' &&
    prev.last_state === currentState &&
    prev.target_path === currentTargetPath &&
    currentState === 'in_progress'
  ) {
    return;
  }

  const nextRevision = (prev.revision || 0) + 1;
  revisions[dlKey] = {
    revision: nextRevision,
    last_state: currentState,
    filename: currentFilename,
    target_path: currentTargetPath,
    updated_at: Date.now()
  };

  // Keep revisions map bounded
  const revEntries = Object.entries(revisions);
  if (revEntries.length > 300) {
    revEntries.sort((a, b) => (a[1].updated_at || 0) - (b[1].updated_at || 0));
    for (let i = 0; i < revEntries.length - 300; i++) {
      delete revisions[revEntries[i][0]];
    }
  }

  const meta = detectBrowserMeta();
  const record = {
    id: `bdl-${state.profile_id}-${dlKey}-r${nextRevision}`,
    kind: 'browser_download',
    data: {
      profile_id: state.profile_id,
      browser_name: meta.browser_name,
      browser_version: meta.browser_version,
      extension_id: meta.extension_id,
      extension_version: meta.extension_version,
      browser_download_id: item.id,
      download_id: item.id,
      revision: nextRevision,
      filename: currentFilename || 'unknown_download',
      final_path: currentTargetPath || null,
      target_path: currentTargetPath || null,
      source_domain: sourceSanitized ? sourceSanitized.domain : 'unknown',
      referrer_domain: referrerSanitized ? referrerSanitized.domain : null,
      mime_type: item.mime || null,
      bytes_received: typeof item.bytesReceived === 'number' ? item.bytesReceived : 0,
      total_bytes: typeof item.totalBytes === 'number' && item.totalBytes >= 0 ? item.totalBytes : null,
      state: currentState,
      danger_type: item.danger || 'safe',
      interrupt_reason: item.error || null,
      start_time: item.startTime || new Date().toISOString(),
      end_time: item.endTime || (currentState !== 'in_progress' ? new Date().toISOString() : null),
      file_exists: typeof item.exists === 'boolean' ? item.exists : null,
      is_incognito: false
    }
  };

  const stats = state.stats || {};
  if (nextRevision === 1) {
    stats.downloads_tracked = (stats.downloads_tracked || 0) + 1;
  }
  await chrome.storage.local.set({ download_revisions: revisions, stats });
  await enqueueAndFlushRecord(record);
}

// 2. Download Lifecycle Listeners
chrome.downloads.onCreated.addListener(async (item) => {
  try {
    await processDownloadItem(item, 'created');
  } catch (err) {
    console.error('AD Monitor download onCreated error:', err);
  }
});

chrome.downloads.onChanged.addListener(async (delta) => {
  try {
    if (!delta || typeof delta.id !== 'number') return;
    // Only emit a state revision when state, filename, danger, error, or completion changes
    if (!delta.state && !delta.filename && !delta.danger && !delta.error && !delta.endTime) {
      return;
    }
    const items = await chrome.downloads.search({ id: delta.id });
    if (items && items.length > 0) {
      await processDownloadItem(items[0], 'changed');
    }
  } catch (err) {
    console.error('AD Monitor download onChanged error:', err);
  }
});

// 3. Extension Lifecycle & Alarms
chrome.runtime.onInstalled.addListener(async () => {
  const state = await ensureStateInitialized();
  await chrome.alarms.create(ALARM_FLUSH, { periodInMinutes: 1 });
  await chrome.alarms.create(ALARM_HEARTBEAT, { periodInMinutes: 5 });
  const meta = detectBrowserMeta();
  const resp = await sendToNativeHost({
    action: 'enroll',
    profile_id: state.profile_id,
    profile_label: state.profile_label || `${meta.browser_name} Work Profile`,
    ...meta
  });
  if (resp && resp.ok) {
    await chrome.storage.local.set({ enrolled: true, paused: false, pause_reason: null });
  }
});

chrome.runtime.onStartup.addListener(async () => {
  const state = await ensureStateInitialized();
  await chrome.alarms.create(ALARM_FLUSH, { periodInMinutes: 1 });
  await chrome.alarms.create(ALARM_HEARTBEAT, { periodInMinutes: 5 });
  const meta = detectBrowserMeta();
  const action = state.enrolled ? 'status' : 'enroll';
  const resp = await sendToNativeHost({
    action,
    profile_id: state.profile_id,
    profile_label: state.profile_label || `${meta.browser_name} Work Profile`,
    ...meta
  });
  if (resp && resp.ok && action === 'enroll') {
    await chrome.storage.local.set({ enrolled: true, paused: false, pause_reason: null });
  }
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === ALARM_FLUSH) {
    await flushPendingQueue();
  } else if (alarm.name === ALARM_HEARTBEAT) {
    const state = await ensureStateInitialized();
    if (state.enrolled) {
      const meta = detectBrowserMeta();
      await sendToNativeHost({
        action: 'heartbeat',
        profile_id: state.profile_id,
        paused: state.paused,
        ...meta
      });
    }
  }
});

// 4. Popup UI Message Handler
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    try {
      const state = await ensureStateInitialized();
      const meta = detectBrowserMeta();

      if (message.type === 'GET_POPUP_STATE') {
        const hostStatus = await sendToNativeHost({
          action: 'status',
          profile_id: state.profile_id,
          ...meta
        });
        const fresh = await chrome.storage.local.get([
          'profile_id',
          'profile_label',
          'enrolled',
          'paused',
          'pause_reason',
          'pending_queue',
          'stats'
        ]);
        sendResponse({
          ok: true,
          profile_id: fresh.profile_id,
          profile_label: fresh.profile_label,
          enrolled: Boolean(fresh.enrolled),
          paused: Boolean(fresh.paused),
          pause_reason: fresh.pause_reason || null,
          extension_queue_depth: Array.isArray(fresh.pending_queue) ? fresh.pending_queue.length : 0,
          browser_meta: meta,
          stats: fresh.stats || {},
          host_status: hostStatus
        });
        return;
      }

      if (message.type === 'ENROLL_PROFILE') {
        const label = (message.profile_label || state.profile_label || `${meta.browser_name} Profile`).trim();
        await chrome.storage.local.set({ profile_label: label });
        const resp = await sendToNativeHost({
          action: 'enroll',
          profile_id: state.profile_id,
          profile_label: label,
          ...meta
        });
        if (resp && resp.ok) {
          await chrome.storage.local.set({ enrolled: true, paused: false, pause_reason: null });
          await flushPendingQueue();
        }
        sendResponse(resp || { ok: false, error: 'No response from native host' });
        return;
      }

      if (message.type === 'TOGGLE_PAUSE') {
        const nextPaused = Boolean(message.paused);
        const reason = message.reason || (nextPaused ? 'Paused by user in extension popup' : 'Resumed by user in extension popup');
        await chrome.storage.local.set({ paused: nextPaused, pause_reason: nextPaused ? reason : null });

        const statusRecord = {
          id: 'bstat-' + crypto.randomUUID(),
          kind: 'browser_status',
          data: {
            profile_id: state.profile_id,
            browser_name: meta.browser_name,
            browser_version: meta.browser_version,
            extension_id: meta.extension_id,
            extension_version: meta.extension_version,
            state: nextPaused ? 'Paused' : 'Enrolled',
            enrollment_state: nextPaused ? 'Paused' : 'Enrolled',
            status: nextPaused ? 'paused' : 'active',
            reason,
            observed_at: new Date().toISOString()
          }
        };
        await enqueueAndFlushRecord(statusRecord);
        sendResponse({ ok: true, paused: nextPaused });
        return;
      }

      if (message.type === 'FLUSH_NOW') {
        const res = await flushPendingQueue();
        sendResponse(res);
        return;
      }

      sendResponse({ ok: false, error: 'Unknown message type' });
    } catch (err) {
      sendResponse({ ok: false, error: err && err.message ? err.message : String(err) });
    }
  })();
  return true;
});
