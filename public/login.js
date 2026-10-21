'use strict';

// Sign-in page. Text is set with textContent only, never innerHTML.

const params = new URLSearchParams(window.location.search);
const MESSAGES = {
  '1': 'Incorrect username or password.',
  locked: 'Too many failed sign-in attempts. Try again later.',
};

// The server checks next again; this only carries it through the form.
document.getElementById('next').value = params.get('next') || '/';

const message = MESSAGES[params.get('error')];
if (message) {
  const box = document.getElementById('login-error');
  box.textContent = message;
  box.hidden = false;
}

const username = document.getElementById('username');
const password = document.getElementById('password');
(username.value ? password : username).focus();
