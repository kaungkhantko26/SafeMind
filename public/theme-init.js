(function initializeTheme() {
  let theme = "";
  try {
    theme = localStorage.getItem("safemind-theme") || "";
  } catch {
    // Fall back to the device preference when storage is unavailable.
  }
  if (theme !== "light" && theme !== "dark") {
    theme = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
})();
