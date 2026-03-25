/**
 * favicon.js — Dynamic favicon and tab title for SentinelGate admin UI.
 *
 * Favicon changes color:
 *   - Teal (#2DD4BF) shield: all OK
 *   - Red (#EF4444) shield: recent denials
 *
 * Tab title updates: "SentinelGate — 3 denied" when there are recent denials.
 * Badge counter rendered via canvas.
 */
'use strict';

window.SG = window.SG || {};

(function () {
  var linkEl = null;
  var lastState = null;
  var defaultTitle = 'SentinelGate';
  var pollInterval = null;

  /**
   * Draw a shield icon on a canvas and return as data URL.
   *
   * @param {string} color - Shield fill color
   * @param {number} [count] - Badge count (0 = no badge)
   * @returns {string} Data URL for the favicon
   */
  function drawFavicon(color, count) {
    var size = 32;
    var canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    var ctx = canvas.getContext('2d');

    // Shield shape
    ctx.beginPath();
    ctx.moveTo(16, 2);
    ctx.lineTo(28, 7);
    ctx.lineTo(28, 16);
    ctx.quadraticCurveTo(28, 27, 16, 30);
    ctx.quadraticCurveTo(4, 27, 4, 16);
    ctx.lineTo(4, 7);
    ctx.closePath();

    ctx.fillStyle = color;
    ctx.fill();

    // Shield outline (slightly darker)
    ctx.strokeStyle = 'rgba(0, 0, 0, 0.2)';
    ctx.lineWidth = 1;
    ctx.stroke();

    // Checkmark (if green/teal state)
    if (!count || count === 0) {
      ctx.beginPath();
      ctx.moveTo(11, 16);
      ctx.lineTo(14, 19);
      ctx.lineTo(21, 12);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.9)';
      ctx.lineWidth = 2.5;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.stroke();
    }

    // Badge counter
    if (count && count > 0) {
      var badgeText = count > 99 ? '99+' : String(count);
      var badgeRadius = badgeText.length > 1 ? 8 : 7;
      var bx = size - badgeRadius - 1;
      var by = badgeRadius + 1;

      // Badge circle
      ctx.beginPath();
      ctx.arc(bx, by, badgeRadius, 0, Math.PI * 2);
      ctx.fillStyle = '#EF4444';
      ctx.fill();
      ctx.strokeStyle = '#0B0D13';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Badge text
      ctx.fillStyle = '#FFFFFF';
      ctx.font = 'bold ' + (badgeText.length > 2 ? '8' : '10') + 'px sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(badgeText, bx, by + 0.5);
    }

    return canvas.toDataURL('image/png');
  }

  /**
   * Update the favicon and tab title based on system state.
   *
   * @param {Object} stats - Stats object from /admin/api/stats
   */
  function updateFavicon(stats) {
    if (!linkEl) {
      linkEl = document.querySelector('link[rel="icon"]');
      if (!linkEl) {
        linkEl = document.createElement('link');
        linkEl.rel = 'icon';
        linkEl.type = 'image/png';
        document.head.appendChild(linkEl);
      }
    }

    var deniedCount = (stats && stats.denied) || 0;
    // We care about recent denials (from the current session's stats)
    var stateKey = deniedCount > 0 ? 'alert-' + deniedCount : 'ok';

    // Skip redraw if nothing changed
    if (stateKey === lastState) return;
    lastState = stateKey;

    if (deniedCount > 0) {
      linkEl.href = drawFavicon('#EF4444', deniedCount);
      document.title = defaultTitle + ' \u2014 ' + deniedCount + ' denied';
    } else {
      linkEl.href = drawFavicon('#2DD4BF', 0);
      document.title = defaultTitle;
    }
  }

  /**
   * Start polling stats for favicon updates.
   * Call once on app init.
   */
  function startFaviconPolling() {
    // L-FE-2: Clear existing interval before starting new one to prevent leak on rapid toggles.
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }

    // Initial draw
    updateFavicon(null);

    pollInterval = setInterval(function () {
      SG.api.get('/stats', { silent: true }).then(function (stats) {
        updateFavicon(stats);
      }).catch(function () {
        // Ignore errors — keep last state
      });
    }, 10000); // every 10 seconds
  }

  function stopFaviconPolling() {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  }

  // -- Public API -----------------------------------------------------------

  SG.favicon = {
    update: updateFavicon,
    startPolling: startFaviconPolling,
    stopPolling: stopFaviconPolling
  };

  // Auto-start on DOMContentLoaded
  document.addEventListener('DOMContentLoaded', function () {
    startFaviconPolling();
  });

  // M-34: pause polling when tab is not visible
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) {
      stopFaviconPolling();
    } else {
      startFaviconPolling();
    }
  });
})();
