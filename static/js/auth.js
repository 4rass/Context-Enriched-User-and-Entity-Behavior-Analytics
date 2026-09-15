'use strict';
document.querySelectorAll('.ce-password-toggle').forEach(button => {
  button.addEventListener('click', () => {
    const input = document.getElementById(button.getAttribute('aria-controls'));
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    button.textContent = show ? 'Hide' : 'Show';
    button.setAttribute('aria-pressed', String(show));
  });
});
document.querySelectorAll('.ce-auth-form').forEach(form => {
  form.addEventListener('submit', event => {
    if (form.dataset.submitting === 'true') { event.preventDefault(); return; }
    form.dataset.submitting = 'true';
    const submit = form.querySelector('.ce-auth-submit');
    submit.disabled = true;
    form.setAttribute('aria-busy', 'true');
    form.querySelector('.ce-auth-progress').textContent = 'Submitting. Please wait.';
  });
});
window.addEventListener('pageshow', () => {
  document.querySelectorAll('.ce-auth-form').forEach(form => {
    delete form.dataset.submitting;
    form.removeAttribute('aria-busy');
    form.querySelector('.ce-auth-submit').disabled = false;
    form.querySelector('.ce-auth-progress').textContent = '';
  });
});
