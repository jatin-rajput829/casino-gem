(function() {
  function initQrCountdown() {
    var countdownEl = document.getElementById('qr-countdown');
    var timerEl = document.getElementById('qr-timer');
    if (!countdownEl || !timerEl) return;

    var expiresAtMs = parseInt(countdownEl.getAttribute('data-expires-at'), 10) * 1000;
    if (isNaN(expiresAtMs)) return;

    var container = countdownEl.closest ? countdownEl.closest('.twofactor') : document;
    var intervalId = null;

    function updateTimer() {
      var remainingSeconds = Math.max(0, Math.ceil((expiresAtMs - Date.now()) / 1000));
      var minutes = Math.floor(remainingSeconds / 60);
      var seconds = remainingSeconds % 60;

      timerEl.textContent =
        (minutes < 10 ? '0' : '') + minutes + ':' +
        (seconds < 10 ? '0' : '') + seconds;

      if (remainingSeconds <= 30) {
        countdownEl.style.color = '#d9534f';
      }

      if (remainingSeconds <= 0) {
        if (intervalId) clearInterval(intervalId);
        countdownEl.innerHTML = '<strong>QR code expired please cancel and try again.</strong>';

        var submitBtn = container.querySelector('form button[type="submit"], form input[type="submit"]');
        var otpInput = container.querySelector('form input[name="otp"]');
        var otpLabel = container.querySelector('form label[for="code"]');

        if (submitBtn) submitBtn.style.display = 'none';
        if (otpInput) {
          otpInput.disabled = true;
          otpInput.style.display = 'none';
        }
        if (otpLabel) otpLabel.style.display = 'none';
      }
    }

    updateTimer();
    intervalId = setInterval(updateTimer, 1000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initQrCountdown);
  } else {
    initQrCountdown();
  }
})();
