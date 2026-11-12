// Shows connection state and the pairing code. No secrets ever pass through here.
const $ = (id) => document.getElementById(id);

chrome.runtime.sendMessage({ type: 'status' }, (s) => {
  if (chrome.runtime.lastError || !s) {
    $('conn').textContent = 'extension error';
    return;
  }
  $('conn').textContent = s.connected ? 'connected to native host' : 'not connected';
  $('pair').textContent = s.pairing;
  $('code').textContent = s.pairingCode ?? '';
  $('hint').textContent =
    s.pairing === 'pending'
      ? 'Compare this code with the dashboard, then confirm there.'
      : s.connected
        ? ''
        : 'Is the broker running and the native host installed?';
});
