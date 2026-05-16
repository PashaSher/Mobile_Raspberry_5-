/**
 * Браузер: подставить iceServers из того же API, что и на Pi (--ice-config-url).
 * Вызовите перед createOffer: pc = new RTCPeerConnection({ iceServers });
 *
 * @param {string} url полный URL, например http://HOST:8788/api/ice
 * @param {string} [token] ICE_CONFIG_TOKEN (Bearer + ?token=)
 * @returns {Promise<RTCIceServer[]>}
 */
export async function fetchIceServersForBrowser(url, token) {
  const headers = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  let fetchUrl = url;
  if (token && !url.includes("token=")) {
    const sep = url.includes("?") ? "&" : "?";
    fetchUrl = `${url}${sep}token=${encodeURIComponent(token)}`;
  }
  const r = await fetch(fetchUrl, { headers });
  if (!r.ok) {
    throw new Error(`ICE API ${r.status}`);
  }
  const data = await r.json();
  const list = data.iceServers;
  if (!Array.isArray(list)) {
    throw new Error("iceServers missing");
  }
  return list;
}
