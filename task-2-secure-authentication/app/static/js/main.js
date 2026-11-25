document.addEventListener("DOMContentLoaded", () => {
  // Password visibility toggle buttons
  document.querySelectorAll("[data-toggle-password]").forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.getAttribute("data-toggle-password");
      if (!targetId) return;
      const input = document.getElementById(targetId);
      if (!(input instanceof HTMLInputElement)) return;

      const isHidden = input.type === "password";
      input.type = isHidden ? "text" : "password";
      button.textContent = isHidden ? "Hide" : "Show";
      button.setAttribute("aria-pressed", String(isHidden));
    });
  });

  // Live visual password policy feedback on registration page (server validation remains authoritative)
  const passwordInput = document.getElementById("password");
  const policyList = document.querySelector(".policy-list");
  if (passwordInput instanceof HTMLInputElement && policyList) {
    const updateRule = (ruleName, passed) => {
      const item = policyList.querySelector(`[data-rule="${ruleName}"]`);
      if (item) {
        item.classList.toggle("rule-met", passed);
      }
    };

    passwordInput.addEventListener("input", () => {
      const val = passwordInput.value;
      updateRule("length", val.length >= 12 && val.length <= 128);
      updateRule("upper", /[A-Z]/.test(val));
      updateRule("lower", /[a-z]/.test(val));
      updateRule("digit", /\d/.test(val));
      updateRule("special", /[^A-Za-z0-9\s]/.test(val));
    });
  }

  // Loading state indicator during form submission
  document.querySelectorAll("[data-loading-form]").forEach((form) => {
    form.addEventListener("submit", () => {
      const submitBtn = form.querySelector("[data-submit-btn]");
      if (submitBtn instanceof HTMLButtonElement) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Processing...";
      }
    });
  });
});
