/**
 * Браузер: WebRTC как при отладке Pi с --ice-vps-only (только TURN на Hetzner).
 *
 *   import { createVpsOnlyPeerConnection } from './webrtc_operator_vps_only.js';
 *   const pc = await createVpsOnlyPeerConnection(
 *     'http://116.203.148.254:8788/api/ice',
 *     'YOUR_ICE_CONFIG_TOKEN'
 *   );
 *
 * Токен — из config/webrtc.ice.local.env (не коммитить).
 */
import { fetchIceServersForBrowser } from "./webrtc_ice_operator_fetch.js";

export function filterTurnOnlyIceServers(iceServers) {
  return iceServers.filter((ent) => {
    const urls = Array.isArray(ent.urls) ? ent.urls : [ent.urls];
    return urls.some((u) => String(u).toLowerCase().startsWith("turn:"));
  });
}

/**
 * @param {string} iceConfigUrl ICE_CONFIG_URL
 * @param {string} iceConfigToken ICE_CONFIG_TOKEN
 * @returns {Promise<RTCPeerConnection>}
 */
export async function createVpsOnlyPeerConnection(iceConfigUrl, iceConfigToken) {
  const all = await fetchIceServersForBrowser(iceConfigUrl, iceConfigToken);
  const turnOnly = filterTurnOnlyIceServers(all);
  if (!turnOnly.length) {
    throw new Error("ICE API: нет turn: — VPS-only невозможен");
  }
  return new RTCPeerConnection({
    iceServers: turnOnly,
    iceTransportPolicy: "relay",
  });
}
