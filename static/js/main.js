// SentinelX - main.js

document.addEventListener("DOMContentLoaded", () => {
  // Sidebar toggle (mobile)
  const toggleBtn = document.getElementById("sidebar-toggle");
  const sidebar = document.querySelector(".sidebar");
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => sidebar.classList.toggle("open"));
  }

  // GSAP entrance animations
  if (window.gsap) {
    gsap.from(".glass-panel, .stat-card, .tool-card", {
      opacity: 0,
      y: 18,
      duration: 0.55,
      stagger: 0.06,
      ease: "power2.out",
    });
    gsap.from(".hero h1, .hero p, .hero-actions", {
      opacity: 0,
      y: 24,
      duration: 0.7,
      stagger: 0.12,
      ease: "power3.out",
    });
  }

  // Progress bar fill animation (data-score attr in %)
  document.querySelectorAll("[data-score]").forEach((el) => {
    const score = parseFloat(el.dataset.score) || 0;
    requestAnimationFrame(() => {
      el.style.width = score + "%";
    });
  });

  // Copy-to-clipboard buttons
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetSelector = btn.getAttribute("data-copy");
      const el = document.querySelector(targetSelector);
      if (!el) return;
      const text = el.innerText || el.value;
      navigator.clipboard.writeText(text).then(() => {
        const original = btn.innerText;
        btn.innerText = "Copied!";
        setTimeout(() => (btn.innerText = original), 1200);
      });
    });
  });

  // Auto-dismiss flash alerts
  document.querySelectorAll(".alert").forEach((alert) => {
    setTimeout(() => {
      alert.style.transition = "opacity 0.4s ease";
      alert.style.opacity = "0";
      setTimeout(() => alert.remove(), 400);
    }, 5000);
  });

  // AI Chat
  const chatForm = document.getElementById("chat-form");
  const chatWindow = document.getElementById("chat-window");
  const chatInput = document.getElementById("chat-input");

  if (chatForm) {
    chatForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const message = chatInput.value.trim();
      if (!message) return;

      appendBubble("user", message);
      chatInput.value = "";
      const typingEl = appendBubble("assistant", "Analyzing...");

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message }),
        });
        const data = await res.json();
        typingEl.innerText = data.reply || "Something went wrong.";
      } catch (err) {
        typingEl.innerText = "Network error. Please try again.";
      }
      chatWindow.scrollTop = chatWindow.scrollHeight;
    });
  }

  function appendBubble(role, text) {
    const div = document.createElement("div");
    div.className = `chat-bubble ${role}`;
    div.innerText = text;
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight;
    return div;
  }
});
