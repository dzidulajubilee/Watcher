/**
 * Watcher — Login page logic (RBAC)
 */

const unInput   = document.getElementById('un');
const pwInput   = document.getElementById('pw');
const eyeBtn    = document.getElementById('eye-btn');
const submitBtn = document.getElementById('submit-btn');
const errorMsg  = document.getElementById('error-msg');

eyeBtn.addEventListener('click', () => {
  pwInput.type = pwInput.type === 'password' ? 'text' : 'password';
});

unInput.addEventListener('keydown', e => { if (e.key === 'Enter') pwInput.focus(); });
pwInput.addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
submitBtn.addEventListener('click', login);

async function login() {
  const username = unInput.value.trim();
  const password = pwInput.value.trim();
  if (!username) { unInput.focus(); showError('Username is required'); return; }
  if (!password) { pwInput.focus(); showError('Password is required'); return; }

  submitBtn.disabled    = true;
  submitBtn.textContent = 'Signing in…';
  errorMsg.style.display = 'none';

  try {
    const res  = await fetch('/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (res.ok && data.ok) {
      window.location.href = '/';
      return;
    }
    showError(data.error || 'Invalid username or password');
    pwInput.value = '';
    pwInput.focus();
  } catch {
    showError('Connection error — is the server running?');
  }

  submitBtn.disabled    = false;
  submitBtn.textContent = 'Sign in';
}

function showError(msg) {
  errorMsg.textContent   = msg;
  errorMsg.style.display = 'block';
}
