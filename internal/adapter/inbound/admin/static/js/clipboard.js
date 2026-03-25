/**
 * clipboard.js — Click-to-copy utility for SentinelGate admin UI.
 *
 * Makes any element copyable with a hover icon and click handler.
 * Shows a brief "Copied!" toast and a green check icon.
 *
 * Usage:
 *   SG.clipboard.makeCopyable(el, 'text to copy');
 *   SG.clipboard.copy('some text', triggerElement);
 */
'use strict';

window.SG = window.SG || {};

(function () {
  var styleInjected = false;

  var COPY_CSS = [
    '.copyable{position:relative;cursor:pointer;display:inline-flex;align-items:center;gap:var(--space-1);transition:color var(--transition-fast)}',
    '.copyable:hover{color:var(--accent-text)}',
    '.copy-icon{opacity:0;transition:opacity var(--transition-fast);width:14px;height:14px;flex-shrink:0;color:var(--text-muted)}',
    '.copyable:hover .copy-icon{opacity:1}',
    '.copyable.copied .copy-icon{color:var(--success);opacity:1}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-clipboard', '');
    s.textContent = COPY_CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  /**
   * Copy text to clipboard and show confirmation.
   *
   * @param {string} text - Text to copy
   * @param {HTMLElement} [triggerEl] - Element to add .copied class to
   */
  function copyToClipboard(text, triggerEl) {
    if (!text) return;

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        onCopied(triggerEl);
      }).catch(function () {
        fallbackCopy(text, triggerEl);
      });
    } else {
      fallbackCopy(text, triggerEl);
    }
  }

  function fallbackCopy(text, triggerEl) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      onCopied(triggerEl);
    } catch (e) {
      SG.toast.error('Failed to copy');
    }
    document.body.removeChild(textarea);
  }

  function onCopied(el) {
    SG.toast.success('Copied to clipboard');
    if (el) {
      el.classList.add('copied');
      setTimeout(function () {
        el.classList.remove('copied');
      }, 1500);
    }
  }

  /**
   * Make an element copyable. Adds a copy icon and click handler.
   *
   * @param {HTMLElement} el - Element to make copyable
   * @param {string} [value] - Value to copy (defaults to el.textContent)
   */
  function makeCopyable(el, value) {
    injectStyles();

    el.classList.add('copyable');
    el.setAttribute('title', 'Click to copy');

    var iconSpan = document.createElement('span');
    iconSpan.className = 'copy-icon';
    if (typeof SG.icon === 'function') {
      iconSpan.innerHTML = SG.icon('copy', 14);
    }
    el.appendChild(iconSpan);

    el.addEventListener('click', function (e) {
      e.stopPropagation();
      // L-28: Extract text without SVG/icon content
      var textToCopy = value;
      if (!textToCopy) {
        var clone = el.cloneNode(true);
        var svgs = clone.querySelectorAll('svg, .copy-icon');
        for (var j = 0; j < svgs.length; j++) {
          svgs[j].parentNode.removeChild(svgs[j]);
        }
        textToCopy = clone.textContent.trim();
      }
      copyToClipboard(textToCopy, el);
    });
  }

  SG.clipboard = {
    copy: copyToClipboard,
    makeCopyable: makeCopyable
  };
})();
