/**
 * Следить за перезапуском webrtc на Pi: при новом hostLaunchId / hostSessionId — снова Connect.
 *
 *   const stopWatch = watchPiHostRelaunch(roomRef, (why) => {
 *     log(`Pi: ${why} — переподключите WebRTC`);
 *     reconnectClient();
 *   });
 */

/**
 * @param {import('firebase/database').DatabaseReference} roomRef rooms/<id>
 * @param {(reason: string) => void} onRelaunch
 * @returns {() => void} detach listeners
 */
export function watchPiHostRelaunch(roomRef, onRelaunch) {
  let lastLaunch = null;
  let lastSession = null;

  const onLaunch = roomRef.child("hostLaunchId").on("value", (snap) => {
    const v = snap.val();
    if (v == null) {
      return;
    }
    if (lastLaunch != null && String(v) !== String(lastLaunch)) {
      onRelaunch(`hostLaunchId ${lastLaunch} → ${v}`);
    }
    lastLaunch = v;
  });

  const onSession = roomRef.child("hostSessionId").on("value", (snap) => {
    const v = snap.val();
    if (v == null) {
      return;
    }
    if (lastSession != null && Number(v) !== Number(lastSession)) {
      onRelaunch(`hostSessionId ${lastSession} → ${v}`);
    }
    lastSession = v;
  });

  const onNeedOffer = roomRef.child("needOffer").on("value", (snap) => {
    if (snap.val() === true && lastLaunch != null) {
      onRelaunch("needOffer=true");
    }
  });

  return () => {
    roomRef.child("hostLaunchId").off("value", onLaunch);
    roomRef.child("hostSessionId").off("value", onSession);
    roomRef.child("needOffer").off("value", onNeedOffer);
  };
}
