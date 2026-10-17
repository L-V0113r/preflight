/**
 * Options page: load settings into the form, save them, test the connection.
 */

import { getSettings, saveSettings } from '../lib/settings.js';

const form = document.getElementById('settings');
const status = document.getElementById('status');

function setStatus(text, kind = '') {
  status.textContent = text;
  status.className = kind;
}

async function load() {
  const settings = await getSettings();
  form.token.value = settings.token;
  form.serverUrl.value = settings.serverUrl;
  form.timeoutSeconds.value = Math.round(settings.timeoutMs / 1000);
  form.querySelector(`input[name="mode"][value="${settings.mode}"]`).checked = true;
  form.querySelector(`input[name="failMode"][value="${settings.failMode}"]`).checked = true;
}

async function save() {
  await saveSettings({
    token: form.token.value,
    serverUrl: form.serverUrl.value,
    mode: form.querySelector('input[name="mode"]:checked').value,
    failMode: form.querySelector('input[name="failMode"]:checked').value,
    timeoutMs: Number(form.timeoutSeconds.value) * 1000,
  });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await save();
    setStatus('Saved.', 'ok');
  } catch (error) {
    setStatus(error.message, 'bad');
  }
});

document.getElementById('test').addEventListener('click', async () => {
  try {
    await save();
  } catch (error) {
    setStatus(error.message, 'bad');
    return;
  }
  setStatus('Testing…');
  const response = await chrome.runtime.sendMessage({ type: 'preflight:health' });
  if (response.status !== 'ok') {
    setStatus(response.message, 'bad');
    return;
  }
  const { health } = response;
  const model = health.model_loaded
    ? `model trained ${String(health.provenance.trained_at).slice(0, 10)}`
    : 'no model loaded (rules only)';
  setStatus(`Connected to PreFlight ${health.version}: ${model}.`, 'ok');
});

load();
