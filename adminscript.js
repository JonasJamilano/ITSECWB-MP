const apiBase = '/admin'; // adjust if needed

// Login form handler
const loginForm = document.getElementById('loginForm');
if (loginForm) {
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const res = await fetch(`${apiBase}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();
    document.getElementById('message').textContent = data.message;

    if (res.ok) {
      localStorage.setItem('token', data.token);
      localStorage.setItem('lastLogin', data.lastLogin);
      window.location.href = 'dashboard.html';
    }
  });
}

// Change password handler
const changeForm = document.getElementById('changePasswordForm');
if (changeForm) {
  changeForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const oldPassword = document.getElementById('oldPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const token = localStorage.getItem('token');

    const res = await fetch(`${apiBase}/change-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token
      },
      body: JSON.stringify({ oldPassword, newPassword }),
    });

    const data = await res.json();
    document.getElementById('message').textContent = data.message;
    if (res.ok) {
      alert("Password changed. Please log in again.");
      localStorage.clear();
      window.location.href = 'login.html';
    }
  });
}
