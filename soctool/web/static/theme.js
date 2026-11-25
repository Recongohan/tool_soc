// Runs before first paint so the saved theme never flashes.
(function () {
  try {
    var saved = localStorage.getItem("soctool-theme");
    if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
  } catch (e) { /* storage blocked - fall back to OS preference */ }
})();
