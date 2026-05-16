/**
 * Trickle ICE через Firebase (обязательно при relay-only / Hetzner).
 *
 * Pi пишет в calleeCandidates, браузер — в callerCandidates.
 * Без подписки на calleeCandidates у ПК сессия часто: answer есть, ICE failed.
 *
 *   import { attachFirebaseIceTrickle } from './webrtc_firebase_ice_trickle.js';
 *   const detach = attachFirebaseIceTrickle(roomRef, pc, 'caller');
 *   // … createOffer, setLocalDescription, push в Firebase …
 *   // после disconnect: detach();
 */

/**
 * @param {import('firebase/database').DatabaseReference} roomRef rooms/<id>
 * @param {RTCPeerConnection} pc
 * @param {'caller'|'callee'} role caller = браузер, callee = Pi
 */
export function attachFirebaseIceTrickle(roomRef, pc, role) {
  const localKey = role === "caller" ? "callerCandidates" : "calleeCandidates";
  const remoteKey = role === "caller" ? "calleeCandidates" : "callerCandidates";

  const seen = new Set();

  pc.addEventListener("icecandidate", (ev) => {
    const c = ev.candidate;
    if (!c) {
      return;
    }
    roomRef.child(localKey).push({
      candidate: c.candidate,
      sdpMid: c.sdpMid,
      sdpMLineIndex: c.sdpMLineIndex,
    });
  });

  const remoteRef = roomRef.child(remoteKey);
  const onAdded = remoteRef.on("child_added", (snap) => {
    const data = snap.val();
    if (!data?.candidate) {
      return;
    }
    const key = data.candidate;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    pc.addIceCandidate(new RTCIceCandidate(data)).catch((err) => {
      console.warn("addIceCandidate remote:", err, data.candidate?.slice(0, 80));
    });
  });

  return () => {
    remoteRef.off("child_added", onAdded);
  };
}
