/**
 * icons.js — Lucide icon SVG definitions for SentinelGate admin UI.
 *
 * Each icon is a complete <svg> string using Lucide's standard attributes:
 *   viewBox="0 0 24 24", stroke="currentColor", fill="none",
 *   stroke-width="2", stroke-linecap="round", stroke-linejoin="round"
 *
 * Usage:
 *   SG.icons.dashboard   // raw SVG string at 20x20
 *   SG.icon('dashboard') // same as above
 *   SG.icon('dashboard', 16) // resized to 16x16
 */
'use strict';

window.SG = window.SG || {};

(function () {
  var ATTRS = 'xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="20" height="20"';

  function svg(inner) {
    return '<svg ' + ATTRS + '>' + inner + '</svg>';
  }

  SG.icons = {
    // Navigation
    dashboard: svg(
      '<rect x="3" y="3" width="7" height="7" rx="1"/>' +
      '<rect x="14" y="3" width="7" height="7" rx="1"/>' +
      '<rect x="3" y="14" width="7" height="7" rx="1"/>' +
      '<rect x="14" y="14" width="7" height="7" rx="1"/>'
    ),

    wrench: svg(
      '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>'
    ),

    key: svg(
      '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>'
    ),

    scrollText: svg(
      '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z"/>' +
      '<path d="M14 2v4a2 2 0 0 0 2 2h4"/>' +
      '<line x1="8" y1="13" x2="16" y2="13"/>' +
      '<line x1="8" y1="17" x2="16" y2="17"/>' +
      '<line x1="8" y1="9" x2="12" y2="9"/>'
    ),

    shield: svg(
      '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'
    ),

    server: svg(
      '<rect width="20" height="8" x="2" y="2" rx="2" ry="2"/>' +
      '<rect width="20" height="8" x="2" y="14" rx="2" ry="2"/>' +
      '<line x1="6" y1="6" x2="6.01" y2="6"/>' +
      '<line x1="6" y1="18" x2="6.01" y2="18"/>'
    ),

    activity: svg(
      '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>'
    ),

    // Status
    checkCircle: svg(
      '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>' +
      '<polyline points="22 4 12 14.01 9 11.01"/>'
    ),

    xCircle: svg(
      '<circle cx="12" cy="12" r="10"/>' +
      '<line x1="15" y1="9" x2="9" y2="15"/>' +
      '<line x1="9" y1="9" x2="15" y2="15"/>'
    ),

    alertTriangle: svg(
      '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>' +
      '<line x1="12" y1="9" x2="12" y2="13"/>' +
      '<line x1="12" y1="17" x2="12.01" y2="17"/>'
    ),

    clock: svg(
      '<circle cx="12" cy="12" r="10"/>' +
      '<polyline points="12 6 12 12 16 14"/>'
    ),

    // Actions
    refreshCw: svg(
      '<polyline points="23 4 23 10 17 10"/>' +
      '<polyline points="1 20 1 14 7 14"/>' +
      '<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>'
    ),

    plus: svg(
      '<line x1="12" y1="5" x2="12" y2="19"/>' +
      '<line x1="5" y1="12" x2="19" y2="12"/>'
    ),

    x: svg(
      '<line x1="18" y1="6" x2="6" y2="18"/>' +
      '<line x1="6" y1="6" x2="18" y2="18"/>'
    ),

    // UI
    chevronDown: svg(
      '<polyline points="6 9 12 15 18 9"/>'
    ),

    chevronRight: svg(
      '<polyline points="9 18 15 12 9 6"/>'
    ),

    info: svg(
      '<circle cx="12" cy="12" r="10"/>' +
      '<line x1="12" y1="16" x2="12" y2="12"/>' +
      '<line x1="12" y1="8" x2="12.01" y2="8"/>'
    ),

    zap: svg(
      '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>'
    ),

    tool: svg(
      '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>'
    ),

    externalLink: svg(
      '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>' +
      '<polyline points="15 3 21 3 21 9"/>' +
      '<line x1="10" y1="14" x2="21" y2="3"/>'
    ),

    copy: svg(
      '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>' +
      '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'
    ),

    compass: svg(
      '<circle cx="12" cy="12" r="10"/>' +
      '<polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/>'
    ),

    globe: svg(
      '<circle cx="12" cy="12" r="10"/>' +
      '<line x1="2" y1="12" x2="22" y2="12"/>' +
      '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>'
    ),

    code: svg(
      '<polyline points="16 18 22 12 16 6"/>' +
      '<polyline points="8 6 2 12 8 18"/>'
    ),

    cpu: svg(
      '<rect x="4" y="4" width="16" height="16" rx="2" ry="2"/>' +
      '<rect x="9" y="9" width="6" height="6"/>' +
      '<line x1="9" y1="1" x2="9" y2="4"/>' +
      '<line x1="15" y1="1" x2="15" y2="4"/>' +
      '<line x1="9" y1="20" x2="9" y2="23"/>' +
      '<line x1="15" y1="20" x2="15" y2="23"/>' +
      '<line x1="20" y1="9" x2="23" y2="9"/>' +
      '<line x1="20" y1="14" x2="23" y2="14"/>' +
      '<line x1="1" y1="9" x2="4" y2="9"/>' +
      '<line x1="1" y1="14" x2="4" y2="14"/>'
    ),

    terminal: svg(
      '<polyline points="4 17 10 11 4 5"/>' +
      '<line x1="12" y1="19" x2="20" y2="19"/>'
    )
  };

  /**
   * Return an icon SVG string, optionally resized.
   *
   * @param {string} name  - Icon key from SG.icons
   * @param {number} [size] - Override width/height (default 20)
   * @returns {string} SVG markup or empty string if not found
   */
  SG.icon = function (name, size) {
    var raw = SG.icons[name];
    if (!raw) { return ''; }
    if (size && size !== 20) {
      return raw
        .replace('width="20"', 'width="' + size + '"')
        .replace('height="20"', 'height="' + size + '"');
    }
    return raw;
  };
})();
