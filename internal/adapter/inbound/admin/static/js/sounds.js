/**
 * sounds.js -- Minimal notification sounds via Web Audio API.
 *
 * No audio files -- all sounds are generated with oscillators.
 * User preference stored in localStorage. Disabled by default.
 *
 * API:
 *   SG.sounds.isEnabled()  - Check if sounds are on
 *   SG.sounds.toggle()     - Toggle on/off (plays confirm when enabling)
 *   SG.sounds.enable()     - Enable sounds
 *   SG.sounds.disable()    - Disable sounds
 *   SG.sounds.alert()      - Descending tones (deny events, security alerts)
 *   SG.sounds.confirm()    - Ascending tones (successful saves)
 *   SG.sounds.click()      - Subtle click (UI interactions)
 *   SG.sounds.error()      - Low buzz (API errors)
 */
'use strict';

window.SG = window.SG || {};

(function () {
  var audioCtx = null;
  var STORAGE_KEY = 'sg-sounds-enabled';

  function isEnabled() {
    try { return localStorage.getItem(STORAGE_KEY) === 'true'; }
    catch (e) { return false; } // L-26: private browsing may throw
  }

  function getContext() {
    if (!audioCtx) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    return audioCtx;
  }

  /**
   * Play a short beep using an oscillator.
   *
   * @param {number} freq     Frequency in Hz
   * @param {number} duration Duration in ms
   * @param {string} type     Oscillator type: 'sine', 'triangle', 'square'
   * @param {number} volume   Gain (0-1)
   */
  function beep(freq, duration, type, volume) {
    if (!isEnabled()) return;

    try {
      var ctx = getContext();
      var osc = ctx.createOscillator();
      var gain = ctx.createGain();

      osc.type = type || 'sine';
      osc.frequency.setValueAtTime(freq, ctx.currentTime);

      gain.gain.setValueAtTime(volume || 0.1, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + (duration / 1000));

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + (duration / 1000));
    } catch (e) {
      // Audio context not available -- silently ignore
    }
  }

  SG.sounds = {
    /** Check if sounds are enabled. */
    isEnabled: isEnabled,

    /** Toggle sounds on/off. Returns new state. */
    toggle: function () {
      var current = isEnabled();
      localStorage.setItem(STORAGE_KEY, String(!current));
      if (!current) {
        SG.sounds.confirm();
      }
      return !current;
    },

    /** Enable sounds. */
    enable: function () { localStorage.setItem(STORAGE_KEY, 'true'); },

    /** Disable sounds. */
    disable: function () { localStorage.setItem(STORAGE_KEY, 'false'); },

    /**
     * Alert sound -- two short descending tones.
     * Use for: Deny events, security alerts.
     */
    alert: function () {
      beep(880, 100, 'triangle', 0.08);
      setTimeout(function () {
        beep(660, 150, 'triangle', 0.06);
      }, 120);
    },

    /**
     * Confirm sound -- ascending tones.
     * Use for: successful saves, rule creation.
     */
    confirm: function () {
      beep(520, 80, 'sine', 0.06);
      setTimeout(function () {
        beep(780, 120, 'sine', 0.04);
      }, 80);
    },

    /**
     * Soft click -- very subtle.
     * Use for: UI interactions, toggles.
     */
    click: function () {
      beep(1200, 30, 'sine', 0.03);
    },

    /**
     * Error sound -- low buzz.
     * Use for: API errors, validation failures.
     */
    error: function () {
      beep(220, 200, 'square', 0.05);
    },

    /**
     * Close the AudioContext to free browser resources.
     * Browsers limit ~6 concurrent AudioContexts.
     */
    cleanup: function () {
      if (audioCtx) {
        try { audioCtx.close(); } catch (e) { /* ignore */ }
        audioCtx = null;
      }
    }
  };

  // Release AudioContext when page unloads
  window.addEventListener('pagehide', function () {
    SG.sounds.cleanup();
  });
})();
