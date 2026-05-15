/**
 * Комната WebRTC signalling в Firebase Realtime Database: /rooms/pi-camera/…
 *
 * Совпадает с Pi по умолчанию (stream_camera.py webrtc без --room).
 *
 * На ПК перед своим кодом добавьте:
 *   <script src="examples/rtdb_room_pi_camera.js"></script>
 *
 * В своём клиенте используйте:
 *   firebase.database().ref("rooms/" + window.__RTDB_WEBRTC_ROOM_ID + "/offer") …
 * или просто строку window.__RTDB_WEBRTC_ROOM_ID.
 */
(globalThis.window || globalThis).__RTDB_WEBRTC_ROOM_ID = "pi-camera";
