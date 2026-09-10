(function () {
  try {
    if (/Android/i.test(navigator.userAgent)) document.documentElement.classList.add("android");
  } catch (_) {}
})();
