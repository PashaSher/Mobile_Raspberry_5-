/**
 * Клавиатура → WebRTC Data Channel тем же JSON, что и TCP `romeo_control_server` на Pi.
 *
 * Цепочка на Pi: Data Channel → `rpi_tools/cli.py::_webrtc_command_handler` →
 * `romeo_control_server._json_to_romeo_lines` → `romeo_exchange` (см. docstring в
 * `rpi_tools/romeo_control_server.py`).
 *
 * Отправка: `JSON.stringify(obj)` без третьего аргумента уже компактный JSON;
 * перевод строки на конце не обязателен — на Pi делается `.strip()` перед `json.loads`.
 *
 * Использование (модуль):
 *   import { attachRomeoWebRtcKeyboard } from './webrtc_browser_control_keys.js';
 *   const detach = attachRomeoWebRtcKeyboard(() => dc, { turretV: 18 });
 *   // detach() — снять слушатели
 *
 * Или в HTML без bundler — подключите как `<script type="module">` и импортируйте,
 * либо скопируйте тело в свой клиент (в т.ч. webrtc-client.html).
 */

/** @typedef {{ turretV?: number, root?: EventTarget }} RomeoKbOptions */

/** @type {Record<string, string>} */
const DRIVE_BY_CODE = {
  KeyW: "forward",
  KeyS: "back",
  KeyA: "left",
  KeyD: "right",
};

/** @type {Record<string, string>} */
const TURRET_BY_CODE = {
  ArrowUp: "up",
  ArrowDown: "down",
  ArrowLeft: "left",
  ArrowRight: "right",
};

/**
 * @param {() => RTCDataChannel | null | undefined} getDc
 * @param {RomeoKbOptions} [opts]
 * @returns {() => void} detach — снять обработчики
 */
export function attachRomeoWebRtcKeyboard(getDc, opts = {}) {
  const root = opts.root ?? (typeof window !== "undefined" ? window : globalThis);
  const turretV = typeof opts.turretV === "number" && opts.turretV > 0 ? opts.turretV : undefined;

  /** @type {string[]} приоритет: индекс 0 = последнее нажатое */
  const driveStack = [];
  /** @type {string[]} то же для стрелок (башня) */
  const turretStack = [];

  let lastDrive = /** @type {string | null} */ (null);
  let lastTurret = /** @type {string | null} */ (null);

  function send(/** @type {Record<string, unknown>} */ obj) {
    const dc = getDc();
    if (!dc || dc.readyState !== "open") return;
    dc.send(JSON.stringify(obj));
  }

  function pickDrive() {
    for (let i = 0; i < driveStack.length; i++) {
      const k = driveStack[i];
      const dir = DRIVE_BY_CODE[k];
      if (dir) return dir;
    }
    return null;
  }

  function pickTurret() {
    for (let i = 0; i < turretStack.length; i++) {
      const code = turretStack[i];
      const dir = TURRET_BY_CODE[code];
      if (dir) return dir;
    }
    return null;
  }

  function syncDrive() {
    const dir = pickDrive();
    if (dir === lastDrive) return;
    lastDrive = dir;
    if (dir) send({ action: "drive", dir });
    else send({ action: "drive", dir: "stop" });
  }

  function syncTurret() {
    const dir = pickTurret();
    if (dir === lastTurret) return;
    lastTurret = dir;
    if (dir) {
      const cmd = /** @type {Record<string, unknown>} */ ({
        action: "turret_smooth",
        dir,
      });
      if (turretV !== undefined) cmd.v = turretV;
      send(cmd);
    } else {
      send({ action: "turret_stop" });
    }
  }

  function stopAll() {
    driveStack.length = 0;
    turretStack.length = 0;
    if (lastDrive !== null) {
      lastDrive = null;
      send({ action: "drive", dir: "stop" });
    }
    if (lastTurret !== null) {
      lastTurret = null;
      send({ action: "turret_stop" });
    }
  }

  /** @param {KeyboardEvent} e */
  function onKeyDown(e) {
    if (e.repeat) return;
    const c = e.code;
    if (DRIVE_BY_CODE[c]) {
      driveStack.splice(driveStack.indexOf(c), 1);
      driveStack.unshift(c);
      syncDrive();
      e.preventDefault();
      return;
    }
    if (TURRET_BY_CODE[c]) {
      turretStack.splice(turretStack.indexOf(c), 1);
      turretStack.unshift(c);
      syncTurret();
      e.preventDefault();
      return;
    }
    if (c === "Space") {
      stopAll();
      e.preventDefault();
    } else if (c === "Escape") {
      stopAll();
      e.preventDefault();
    }
  }

  /** @param {KeyboardEvent} e */
  function onKeyUp(e) {
    const c = e.code;
    if (DRIVE_BY_CODE[c]) {
      const i = driveStack.indexOf(c);
      if (i >= 0) driveStack.splice(i, 1);
      syncDrive();
      e.preventDefault();
      return;
    }
    if (TURRET_BY_CODE[c]) {
      const ti = turretStack.indexOf(c);
      if (ti >= 0) turretStack.splice(ti, 1);
      syncTurret();
      e.preventDefault();
    }
  }

  function onBlur() {
    stopAll();
  }

  root.addEventListener("keydown", onKeyDown, true);
  root.addEventListener("keyup", onKeyUp, true);
  /** @type {Window | EventTarget} */
  const blurEt =
    typeof window !== "undefined" &&
    typeof Window !== "undefined" &&
    root instanceof Node &&
    !(root instanceof Window)
      ? window
      : /** @type {Window | EventTarget} */ (root);
  blurEt.addEventListener("blur", onBlur);

  return function detach() {
    stopAll();
    root.removeEventListener("keydown", onKeyDown, true);
    root.removeEventListener("keyup", onKeyUp, true);
    blurEt.removeEventListener("blur", onBlur);
  };
}

if (typeof globalThis !== "undefined") {
  globalThis.attachRomeoWebRtcKeyboard = attachRomeoWebRtcKeyboard;
}
