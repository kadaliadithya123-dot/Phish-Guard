/**
 * PHISH GUARD - Content Script (Hybrid Multi-Modal Collector)
 * Extracts full webpage HTML source, DOM structure, forms, input fields,
 * script metadata, images, and detects evasive interaction blockers.
 */

(function () {
  if (window.__PHISH_GUARD_CONTENT_INJECTED__) return;
  window.__PHISH_GUARD_CONTENT_INJECTED__ = true;

  /**
   * Deeply extracts webpage components, form metadata, scripts, and images.
   */
  function extractPageData() {
    const url = window.location.href;
    const title = document.title || "";

    // 1. Favicon
    let faviconUrl = "";
    const favLink = document.querySelector('link[rel~="icon"]') || document.querySelector('link[rel="shortcut icon"]');
    if (favLink && favLink.href) {
      faviconUrl = favLink.href;
    }

    // 2. Forms & Inputs
    const forms = [];
    document.querySelectorAll("form").forEach((f) => {
      const inputs = [];
      f.querySelectorAll("input, select, textarea").forEach((inp) => {
        inputs.push({
          type: (inp.type || "text").toLowerCase(),
          name: (inp.name || "").toLowerCase(),
          id: (inp.id || "").toLowerCase(),
          placeholder: (inp.placeholder || "").toLowerCase()
        });
      });

      forms.push({
        action: f.getAttribute("action") || f.action || "",
        method: (f.method || "GET").toUpperCase(),
        inputs: inputs
      });
    });

    // Also collect standalone inputs not inside any form
    const standaloneInputs = [];
    document.querySelectorAll("body > input, div > input").forEach((inp) => {
      if (!inp.closest("form")) {
        standaloneInputs.push({
          type: (inp.type || "text").toLowerCase(),
          name: (inp.name || "").toLowerCase(),
          id: (inp.id || "").toLowerCase(),
          placeholder: (inp.placeholder || "").toLowerCase()
        });
      }
    });
    if (standaloneInputs.length > 0) {
      forms.push({
        action: "",
        method: "STANDALONE",
        inputs: standaloneInputs
      });
    }

    // 3. Scripts
    const scripts = [];
    document.querySelectorAll("script").forEach((s) => {
      scripts.push({
        src: s.src || "",
        content: s.textContent ? s.textContent.slice(0, 3000) : ""
      });
    });

    // 4. Images
    const images = [];
    document.querySelectorAll("img").forEach((img) => {
      images.push({
        src: img.src || img.getAttribute("data-src") || "",
        alt: img.alt || "",
        width: img.naturalWidth || img.width || 0,
        height: img.naturalHeight || img.height || 0
      });
    });

    // 5. Interaction Blocking & Evasion Checks
    const isContextMenuDisabled = (
      document.oncontextmenu !== null ||
      document.body?.oncontextmenu !== null ||
      document.documentElement.getAttribute("oncontextmenu") !== null
    );

    // 6. Safe HTML Source slice (preserves complete head and body structures)
    const rawHtml = document.documentElement ? document.documentElement.outerHTML.slice(0, 150000) : "";

    return {
      url: url,
      title: title,
      html: rawHtml,
      favicon_url: faviconUrl,
      forms: forms,
      scripts: scripts,
      images: images,
      dom_metrics: {
        context_menu_disabled: isContextMenuDisabled,
        total_elements: document.getElementsByTagName("*").length
      }
    };
  }

  // Send extracted data upon initial page load
  function notifyBackground() {
    try {
      const payload = extractPageData();
      chrome.runtime.sendMessage({
        action: "PAGE_CONTENT_EXTRACTED",
        payload: payload
      });
    } catch (e) {
      // Context invalidated on tab refresh
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", notifyBackground);
  } else {
    notifyBackground();
  }

  // Handle on-demand requests from background or popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "REQUEST_PAGE_CONTENT") {
      const payload = extractPageData();
      sendResponse({ status: "success", payload: payload });
    }
    return true;
  });

  // Dynamic Mutation Observer (detects phishing overlays or late-injected login dialogs)
  let mutationTimeout = null;
  const observer = new MutationObserver(() => {
    if (mutationTimeout) clearTimeout(mutationTimeout);
    mutationTimeout = setTimeout(() => {
      // Re-scan if dynamic password input was injected
      if (document.querySelector('input[type="password"]')) {
        notifyBackground();
      }
    }, 1500);
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();
