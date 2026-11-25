/* =========================================================================
   ORIGIN MATH — NỀN TẢNG LUYỆN ĐỀ & KHẢO THÍ TOÁN THPT (BẢN CHUẨN ĐỒNG BỘ)
========================================================================= */

const FIREBASE_CONFIG = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT.firebaseapp.com",
  projectId: "YOUR_PROJECT_ID",
  storageBucket: "YOUR_PROJECT.appspot.com",
  messagingSenderId: "YOUR_SENDER_ID",
  appId: "YOUR_APP_ID"
};

const _OM_VAULT = Object.freeze({
  s1: "9f4c2a8e7b1d6053c8a1f3e2d4b79016",
  s2: "3e7b91d4a0c582f6e1b37d9a4c2058ef",
  it: 5000,
  u: "09dc63e6c6349838336609a3ea8c629c336b90ab5bf0da18d6bd5fc611767bf3",
  p: "7fff9412eb83e0118f96e7ad2045b5eaf8dcb9719fe73f80262c1c241da0a725"
});

const ACCENT_HEX = {
  indigo: ["#4f46e5", "#0ea5e9"],
  emerald: ["#059669", "#14b8a6"],
  sky: ["#0284c7", "#38bdf8"],
  rose: ["#e11d48", "#fb7185"],
  amber: ["#d97706", "#fbbf24"],
  violet: ["#7c3aed", "#c084fc"]
};

const USERNAME_REGEX = /^[a-z0-9_]{4,24}$/;
const syncChannel = typeof BroadcastChannel !== "undefined" ? new BroadcastChannel("origin_math_v8_realtime") : null;

// ---------------- MÃ HÓA PBKDF2-HMAC-SHA256 ----------------
const CryptoEngine = (() => {
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  function toBytes(str) { return new TextEncoder().encode(str); }
  function sha256Bytes(msg) {
    const l = msg.length, bitLen = l * 8;
    const padLen = ((l + 9 + 63) >> 6) << 6;
    const b = new Uint8Array(padLen);
    b.set(msg); b[l] = 0x80;
    const dv = new DataView(b.buffer);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(padLen - 4, bitLen >>> 0, false);
    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    const w = new Uint32Array(64);
    for (let i = 0; i < padLen; i += 64) {
      for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, false);
      for (let j = 16; j < 64; j++) {
        const s0 = ((w[j-15]>>>7)|(w[j-15]<<25)) ^ ((w[j-15]>>>18)|(w[j-15]<<14)) ^ (w[j-15]>>>3);
        const s1 = ((w[j-2]>>>17)|(w[j-2]<<15)) ^ ((w[j-2]>>>19)|(w[j-2]<<13)) ^ (w[j-2]>>>10);
        w[j] = (w[j-16] + s0 + w[j-7] + s1) >>> 0;
      }
      let a=h0,bb=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for (let j = 0; j < 64; j++) {
        const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[j] + w[j]) >>> 0;
        const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
        const maj = (a & bb) ^ (a & c) ^ (bb & c);
        const t2 = (S0 + maj) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=bb; bb=a; a=(t1+t2)>>>0;
      }
      h0=(h0+a)>>>0; h1=(h1+bb)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
      h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
    }
    const out = new Uint8Array(32), odv = new DataView(out.buffer);
    [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v, idx) => odv.setUint32(idx * 4, v, false));
    return out;
  }
  function hmacSha256(keyBytes, dataBytes) {
    const k = new Uint8Array(64);
    k.set(keyBytes.length > 64 ? sha256Bytes(keyBytes) : keyBytes);
    const oPad = new Uint8Array(64), iPad = new Uint8Array(64);
    for (let i = 0; i < 64; i++) { oPad[i] = k[i] ^ 0x5c; iPad[i] = k[i] ^ 0x36; }
    const inner = new Uint8Array(64 + dataBytes.length);
    inner.set(iPad); inner.set(dataBytes, 64);
    const ih = sha256Bytes(inner);
    const outer = new Uint8Array(96);
    outer.set(oPad); outer.set(ih, 64);
    return sha256Bytes(outer);
  }
  function toHex(bytes) { return Array.from(bytes).map(x => x.toString(16).padStart(2, "0")).join(""); }
  function pbkdf2HexSync(secret, salt, iterations = 5000) {
    const pwd = toBytes(secret), s = toBytes(salt);
    const block = new Uint8Array(s.length + 4);
    block.set(s); block[s.length + 3] = 1;
    let u = hmacSha256(pwd, block);
    const acc = new Uint8Array(u);
    for (let i = 1; i < iterations; i++) {
      u = hmacSha256(pwd, u);
      for (let j = 0; j < 32; j++) acc[j] ^= u[j];
    }
    return toHex(acc);
  }
  async function pbkdf2Hex(secret, salt, iterations = 5000) {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      try {
        const key = await crypto.subtle.importKey("raw", toBytes(secret), "PBKDF2", false, ["deriveBits"]);
        const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: toBytes(salt), iterations, hash: "SHA-256" }, key, 256);
        return toHex(new Uint8Array(bits));
      } catch (_) {}
    }
    return pbkdf2HexSync(secret, salt, iterations);
  }
  function constantTimeEq(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }
  return { pbkdf2Hex, constantTimeEq };
})();

// ---------------- BẢO VỆ CHỐNG XEM MÃ NGUỒN (F12, CTRL+U, CTRL+SHIFT+I/J/C, CHUỘT PHẢI, VIEW-SOURCE) TOÀN TRANG ----------------
(function initAntiSourceProtection() {
  document.addEventListener("contextmenu", (e) => {
    const isEditable = ["INPUT", "TEXTAREA"].includes(e.target.tagName) || e.target.isContentEditable;
    if (!isEditable) e.preventDefault();
  }, true);

  document.addEventListener("keydown", (e) => {
    const k = (e.key || "").toUpperCase();
    const code = (e.code || "").toUpperCase();
    const ctrl = e.ctrlKey || e.metaKey;

    const isDevToolsShortcut =
      k === "F12" || code === "F12" || e.keyCode === 123 ||
      (ctrl && e.shiftKey && ["I", "J", "C", "K", "M", "E"].includes(k)) ||
      (ctrl && ["U", "S", "P"].includes(k)) ||
      (e.metaKey && e.altKey && ["I", "J", "C", "U"].includes(k));

    if (isDevToolsShortcut) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      if (state.examSession.active) {
        recordExamViolation("Phát hiện phím tắt bị cấm trong phòng thi (" + k + ").");
      } else {
        showToast("Tính năng xem mã nguồn & công cụ kiểm tra phần tử đã bị khóa.", "warn");
      }
      return false;
    }

    if (state.examSession.active) {
      if ((ctrl && ["C", "V", "X", "A", "F", "H", "R"].includes(k)) || k === "F11" || k === "F5" || k === "ESCAPE") {
        e.preventDefault();
        e.stopPropagation();
        recordExamViolation("Phát hiện thao tác phím cấm trong phòng thi (" + k + ").");
      }
    } else if (ctrl && k === "Z" && state.pracSession.active && wbState.ready) {
      e.preventDefault();
      wbUndo();
    }
  }, true);

  // Phát hiện mở DevTools thông qua kích thước cửa sổ hoặc debugger timing khi đang thi
  setInterval(() => {
    if (!state.examSession.active || state.examSession.submitting || state.examSession.disqualified) return;
    const widthDiff = window.outerWidth - window.innerWidth > 180;
    const heightDiff = window.outerHeight - window.innerHeight > 180;
    if (widthDiff || heightDiff) {
      recordExamViolation("Phát hiện mở công cụ trình duyệt / thu hẹp cửa sổ khi đang thi.");
    }
  }, 1500);
})();

function getDefaultAvatar(gender = "Nam") {
  const isFemale = gender === "Nữ";
  const bg = isFemale ? "%23ec4899" : "%234f46e5";
  const hair = isFemale ? "%23312e81" : "%231e293b";
  const svg = isFemale
    ? `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='50' fill='${bg}'/><circle cx='50' cy='42' r='22' fill='${hair}'/><circle cx='50' cy='40' r='16' fill='%23fde68a'/><path d='M24 88 C24 64 76 64 76 88' fill='%23ffffff'/></svg>`
    : `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='50' fill='${bg}'/><path d='M32 34 C34 18 66 18 68 34' fill='${hair}'/><circle cx='50' cy='40' r='16' fill='%23fde68a'/><path d='M24 88 C24 64 76 64 76 88' fill='%23ffffff'/></svg>`;
  return `data:image/svg+xml;utf8,${svg}`;
}

const DEFAULT_SETS = [];
let fbAuth = null, fbDb = null, isFirebaseLive = false;

const DEFAULT_PREFS = {
  dark: false, accent: "indigo", bg: "grid", customBg: "", blur: 14,
  sound: true, marqueeOn: false, marqueeText: "ORIGIN MATH",
  marqueeOpacity: 7, collapsed: false, holidayAuto: true, holidayPreview: "auto"
};

const state = {
  user: JSON.parse(localStorage.getItem("om_v8_user") || "null"),
  usersMap: JSON.parse(localStorage.getItem("om_v8_users_map") || "{}"),
  sets: JSON.parse(localStorage.getItem("om_v8_sets") || "null") || DEFAULT_SETS,
  submissions: JSON.parse(localStorage.getItem("om_v8_subs") || "[]"),
  participants: JSON.parse(localStorage.getItem("om_v8_parts") || "[]"),
  handwrittenSolutions: JSON.parse(localStorage.getItem("om_v8_hw_sols") || "{}"),
  prefs: { ...DEFAULT_PREFS, ...JSON.parse(localStorage.getItem("om_v8_prefs") || "{}") },
  parsedWordQuestions: [],
  parsedEssayHTML: "",
  lastFocusedEditor: null,
  authMode: "login",
  activeHoliday: null,
  pracSession: {
    active: false, set: null, questions: [], idx: 0, answers: {},
    scores: {}, qTimes: {}, timeLeft: 0, timerId: null,
    submitted: false, isRetryWrong: false, boardSnapshots: {}
  },
  examSession: {
    active: false, set: null, questions: [], answers: {}, flags: {},
    activeIdx: 0, qTimes: {}, timeLeft: 0, timerId: null,
    violations: [], submitting: false, disqualified: false
  }
};

function reloadStateFromStorage() {
  state.usersMap = JSON.parse(localStorage.getItem("om_v8_users_map") || "{}");
  state.sets = JSON.parse(localStorage.getItem("om_v8_sets") || "[]");
  state.submissions = JSON.parse(localStorage.getItem("om_v8_subs") || "[]");
  state.participants = JSON.parse(localStorage.getItem("om_v8_parts") || "[]");
  state.handwrittenSolutions = JSON.parse(localStorage.getItem("om_v8_hw_sols") || "{}");

  if (state.user) {
    if (!state.usersMap[state.user.uid] && state.user.uid !== "admin-root") {
      state.user = null;
      localStorage.removeItem("om_v8_user");
    } else if (state.usersMap[state.user.uid]) {
      state.user = { ...state.user, ...state.usersMap[state.user.uid] };
      localStorage.setItem("om_v8_user", JSON.stringify(state.user));
    }
    renderUserUI();
  }
  refreshAllViews();
  if (state.pracSession.active && state.pracSession.set) {
    renderHandwrittenSolutionView(state.pracSession.set.id);
  }
}

function saveAndBroadcast(type = "sync") {
  try {
    if (state.user) localStorage.setItem("om_v8_user", JSON.stringify(state.user));
    else localStorage.removeItem("om_v8_user");
    localStorage.setItem("om_v8_users_map", JSON.stringify(state.usersMap));
    localStorage.setItem("om_v8_sets", JSON.stringify(state.sets));
    localStorage.setItem("om_v8_subs", JSON.stringify(state.submissions));
    localStorage.setItem("om_v8_parts", JSON.stringify(state.participants));
    localStorage.setItem("om_v8_hw_sols", JSON.stringify(state.handwrittenSolutions));
    localStorage.setItem("om_v8_prefs", JSON.stringify(state.prefs));
  } catch (err) {
    console.warn("Storage warning:", err);
  }
  if (syncChannel) syncChannel.postMessage({ type, ts: Date.now() });
}

// Đồng bộ tức thì qua cả BroadcastChannel lẫn sự kiện storage (đa tab / đa cửa sổ)
if (syncChannel) {
  syncChannel.onmessage = () => reloadStateFromStorage();
}
window.addEventListener("storage", (e) => {
  if (e.key && e.key.startsWith("om_v8_")) reloadStateFromStorage();
});

function initFirebase() {
  const configured = FIREBASE_CONFIG.apiKey && FIREBASE_CONFIG.apiKey !== "YOUR_API_KEY";
  const statusEl = document.getElementById("sync-status-text");
  if (!configured || typeof firebase === "undefined") {
    if (statusEl) statusEl.textContent = "Đồng bộ Live";
    return;
  }
  try {
    firebase.initializeApp(FIREBASE_CONFIG);
    fbAuth = firebase.auth();
    fbDb = firebase.firestore();
    isFirebaseLive = true;
    if (statusEl) statusEl.textContent = "Cloud Realtime";
    fbAuth.setPersistence(firebase.auth.Auth.Persistence.LOCAL).catch(() => {});

    fbDb.collection("users").onSnapshot((snap) => {
      const nextMap = {};
      snap.docs.forEach(d => { nextMap[d.id] = { uid: d.id, ...d.data() }; });
      state.usersMap = nextMap;
      if (state.user && state.user.uid !== "admin-root" && !state.usersMap[state.user.uid]) {
        state.user = null;
        localStorage.removeItem("om_v8_user");
        renderUserUI();
      } else if (state.user && state.usersMap[state.user.uid]) {
        state.user = { ...state.user, ...state.usersMap[state.user.uid] };
        localStorage.setItem("om_v8_user", JSON.stringify(state.user));
        renderUserUI();
      }
      refreshAllViews();
    });

    fbDb.collection("exams").orderBy("createdAt", "desc").onSnapshot((snap) => {
      state.sets = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      refreshAllViews();
    });

    fbDb.collection("submissions").orderBy("submittedAt", "desc").onSnapshot((snap) => {
      state.submissions = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      refreshAllViews();
    });

    fbDb.collection("participants").onSnapshot((snap) => {
      state.participants = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      renderMonitorTable();
    });

    fbDb.collection("handwrittenSolutions").onSnapshot((snap) => {
      snap.docs.forEach(d => { state.handwrittenSolutions[d.id] = d.data(); });
      if (state.pracSession.active && state.pracSession.set) {
        renderHandwrittenSolutionView(state.pracSession.set.id);
      }
    });

    fbAuth.onAuthStateChanged(async (fbUser) => {
      if (!fbUser) {
        if (state.user && state.user.uid !== "admin-root") {
          state.user = null;
          localStorage.removeItem("om_v8_user");
          renderUserUI();
        }
        return;
      }
      const doc = await fbDb.collection("users").doc(fbUser.uid).get().catch(() => null);
      if (!doc || !doc.exists) {
        await fbAuth.signOut().catch(() => {});
        state.user = null;
        localStorage.removeItem("om_v8_user");
        renderUserUI();
        return;
      }
      const data = doc.data();
      state.user = {
        uid: fbUser.uid,
        name: data.name || fbUser.email.split("@")[0],
        username: data.username || fbUser.email.split("@")[0],
        grade: data.grade || "12",
        gender: data.gender || "Nam",
        dob: data.dob || "",
        role: data.role || "student",
        grantedTracks: data.grantedTracks || [],
        avatar: data.avatar || getDefaultAvatar(data.gender || "Nam")
      };
      if (data.prefs) { state.prefs = { ...state.prefs, ...data.prefs }; applyPreferences(); }
      localStorage.setItem("om_v8_user", JSON.stringify(state.user));
      renderUserUI();
      refreshAllViews();
    });
  } catch (e) { console.error(e); }
}

// ---------------- LỄ HỘI VIỆT NAM & THẾ GIỚI ----------------
const LunarVN = (() => {
  const PI = Math.PI;
  function jdFromDate(dd, mm, yy) {
    const a = Math.floor((14 - mm) / 12);
    const y = yy + 4800 - a;
    const m = mm + 12 * a - 3;
    let jd = dd + Math.floor((153 * m + 2) / 5) + 365 * y + Math.floor(y / 4) - Math.floor(y / 100) + Math.floor(y / 400) - 32045;
    if (jd < 2299161) jd = dd + Math.floor((153 * m + 2) / 5) + 365 * y + Math.floor(y / 4) - 32083;
    return jd;
  }
  function getNewMoonDay(k, tz) {
    const T = k / 1236.85, T2 = T * T, T3 = T2 * T, dr = PI / 180;
    let Jd1 = 2415020.75933 + 29.53058868 * k + 0.0001178 * T2 - 0.000000155 * T3;
    Jd1 += 0.00033 * Math.sin((166.56 + 132.87 * T - 0.009173 * T2) * dr);
    const M = 359.2242 + 29.10535608 * k - 0.0000333 * T2 - 0.00000347 * T3;
    const Mpr = 306.0253 + 385.81691806 * k + 0.0107306 * T2 + 0.00001236 * T3;
    const F = 21.2964 + 390.67050646 * k - 0.0016528 * T2 - 0.00000239 * T3;
    let C1 = (0.1734 - 0.000393 * T) * Math.sin(M * dr) + 0.0021 * Math.sin(2 * dr * M);
    C1 = C1 - 0.4068 * Math.sin(Mpr * dr) + 0.0161 * Math.sin(dr * 2 * Mpr) - 0.0004 * Math.sin(dr * 3 * Mpr);
    C1 = C1 + 0.0104 * Math.sin(dr * 2 * F) - 0.0051 * Math.sin(dr * (M + Mpr)) - 0.0074 * Math.sin(dr * (M - Mpr));
    C1 = C1 + 0.0004 * Math.sin(dr * (2 * F + M)) - 0.0004 * Math.sin(dr * (2 * F - M)) - 0.0006 * Math.sin(dr * (2 * F + Mpr));
    C1 = C1 + 0.0010 * Math.sin(dr * (2 * F - Mpr)) + 0.0005 * Math.sin(dr * (2 * Mpr + M));
    const deltat = T < -11 ? 0.001 + 0.000839 * T + 0.0002261 * T2 - 0.00000845 * T3 - 0.000000081 * T * T3 : -0.000278 + 0.000265 * T + 0.000262 * T2;
    return Math.floor(Jd1 + C1 - deltat + 0.5 + tz / 24);
  }
  function getSunLongitude(jdn, tz) {
    const T = (jdn - 2451545.5 - tz / 24) / 36525, T2 = T * T, dr = PI / 180;
    const M = 357.52910 + 35999.05030 * T - 0.0001559 * T2 - 0.00000048 * T * T2;
    const L0 = 280.46645 + 36000.76983 * T + 0.0003032 * T2;
    let DL = (1.914600 - 0.004817 * T - 0.000014 * T2) * Math.sin(dr * M) + (0.019993 - 0.000101 * T) * Math.sin(dr * 2 * M) + 0.000290 * Math.sin(dr * 3 * M);
    let L = (L0 + DL) * dr;
    L = L - PI * 2 * Math.floor(L / (PI * 2));
    return Math.floor(L / PI * 6);
  }
  function getLunarMonth11(yy, tz) {
    const off = jdFromDate(31, 12, yy) - 2415021;
    const k = Math.floor(off / 29.530588853);
    let nm = getNewMoonDay(k, tz);
    if (getSunLongitude(nm, tz) >= 9) nm = getNewMoonDay(k - 1, tz);
    return nm;
  }
  function getLeapMonthOffset(a11, tz) {
    const k = Math.floor((a11 - 2415021.076998695) / 29.530588853 + 0.5);
    let last = 0, i = 1, arc = getSunLongitude(getNewMoonDay(k + i, tz), tz);
    do { last = arc; i++; arc = getSunLongitude(getNewMoonDay(k + i, tz), tz); } while (arc !== last && i < 14);
    return i - 1;
  }
  function solarToLunar(dd, mm, yy, tz = 7) {
    const dayNumber = jdFromDate(dd, mm, yy);
    const k = Math.floor((dayNumber - 2415021.076998695) / 29.530588853);
    let monthStart = getNewMoonDay(k + 1, tz);
    if (monthStart > dayNumber) monthStart = getNewMoonDay(k, tz);
    let a11 = getLunarMonth11(yy, tz), b11 = a11, lunarYear;
    if (a11 >= monthStart) { lunarYear = yy; a11 = getLunarMonth11(yy - 1, tz); }
    else { lunarYear = yy + 1; b11 = getLunarMonth11(yy + 1, tz); }
    const lunarDay = dayNumber - monthStart + 1;
    const diff = Math.floor((monthStart - a11) / 29);
    let lunarMonth = diff + 11;
    if (b11 - a11 > 365) {
      const leapOff = getLeapMonthOffset(a11, tz);
      if (diff >= leapOff) lunarMonth = diff + 10;
    }
    if (lunarMonth > 12) lunarMonth -= 12;
    if (lunarMonth >= 11 && diff < 4) lunarYear -= 1;
    return { day: lunarDay, month: lunarMonth, year: lunarYear };
  }
  return { solarToLunar };
})();

const HOLIDAY_CATALOG = {
  tet: { id: "tet", icon: "🧧", title: "Chúc Mừng Năm Mới — Tết Nguyên Đán!", sub: "An khang thịnh vượng • Vạn sự như ý!", colors: ["#dc2626", "#f59e0b"], fx: "blossom" },
  newyear: { id: "newyear", icon: "🎆", title: "Happy New Year!", sub: "Khởi đầu rực rỡ cùng Origin Math!", colors: ["#d97706", "#f59e0b"], fx: "sparkle" },
  valentine: { id: "valentine", icon: "💝", title: "Happy Valentine's Day 14/02", sub: "Chúc các bạn học tập thật hăng say!", colors: ["#e11d48", "#fb7185"], fx: "hearts" },
  women83: { id: "women83", icon: "🌷", title: "Chúc Mừng Ngày Quốc Tế Phụ Nữ 08/03", sub: "Chúc các cô giáo và nữ sinh luôn rạng rỡ!", colors: ["#db2777", "#f472b6"], fx: "blossom" },
  hungkings: { id: "hungkings", icon: "🏮", title: "Giỗ Tổ Hùng Vương (10/03 Âm lịch)", sub: "Nhớ ngày Giỗ Tổ mùng mười tháng ba.", colors: ["#b45309", "#f59e0b"], fx: "sparkle" },
  liberation: { id: "liberation", icon: "🇻🇳", title: "Chào Mừng 30/04 & Quốc Tế Lao Động 01/05", sub: "Chúc kỳ nghỉ lễ vui vẻ và ý nghĩa!", colors: ["#dc2626", "#eab308"], fx: "stars" },
  nationalday: { id: "nationalday", icon: "🇻🇳", title: "Chào Mừng Quốc Khánh Việt Nam 02/09", sub: "Tự hào Việt Nam — Không ngừng vươn xa!", colors: ["#dc2626", "#facc15"], fx: "stars" },
  midautumn: { id: "midautumn", icon: "🥮", title: "Vui Tết Trung Thu (15/08 Âm lịch)", sub: "Đêm hội trăng rằm ấm áp bên gia đình!", colors: ["#ca8a04", "#6366f1"], fx: "lantern" },
  women2010: { id: "women2010", icon: "💐", title: "Chúc Mừng Ngày Phụ Nữ Việt Nam 20/10", sub: "Chúc các cô giáo và các bạn nữ sinh luôn tỏa sáng!", colors: ["#db2777", "#fb7185"], fx: "blossom" },
  halloween: { id: "halloween", icon: "🎃", title: "Happy Halloween 31/10!", sub: "Rèn luyện vững vàng, chinh phục mọi bài toán!", colors: ["#ea580c", "#7c3aed"], fx: "sparkle" },
  teachers: { id: "teachers", icon: "🎓", title: "Chào Mừng Ngày Nhà Giáo Việt Nam 20/11", sub: "Tri ân quý thầy cô — Những người lái đò tri thức!", colors: ["#0284c7", "#f59e0b"], fx: "blossom" },
  christmas: { id: "christmas", icon: "🎄", title: "Merry Christmas — Giáng Sinh An Lành!", sub: "Mùa đông ấm áp cùng Origin Math!", colors: ["#15803d", "#dc2626"], fx: "snow" }
};

function detectRealtimeHoliday() {
  const now = new Date();
  const vn = new Date(now.getTime() + (now.getTimezoneOffset() + 420) * 60000);
  const d = vn.getDate(), m = vn.getMonth() + 1, y = vn.getFullYear();
  const lunar = LunarVN.solarToLunar(d, m, y, 7);

  if ((lunar.month === 12 && lunar.day >= 28) || (lunar.month === 1 && lunar.day <= 5)) return HOLIDAY_CATALOG.tet;
  if (lunar.month === 3 && lunar.day >= 9 && lunar.day <= 10) return HOLIDAY_CATALOG.hungkings;
  if (lunar.month === 8 && lunar.day >= 14 && lunar.day <= 15) return HOLIDAY_CATALOG.midautumn;

  if ((m === 12 && d === 31) || (m === 1 && d <= 2)) return HOLIDAY_CATALOG.newyear;
  if (m === 2 && d === 14) return HOLIDAY_CATALOG.valentine;
  if (m === 3 && d === 8) return HOLIDAY_CATALOG.women83;
  if ((m === 4 && d >= 29) || (m === 5 && d <= 1)) return HOLIDAY_CATALOG.liberation;
  if (m === 9 && d >= 1 && d <= 3) return HOLIDAY_CATALOG.nationalday;
  if (m === 10 && d === 20) return HOLIDAY_CATALOG.women2010;
  if (m === 10 && d >= 30) return HOLIDAY_CATALOG.halloween;
  if (m === 11 && d >= 19 && d <= 20) return HOLIDAY_CATALOG.teachers;
  if (m === 12 && d >= 22 && d <= 26) return HOLIDAY_CATALOG.christmas;
  return null;
}

let holidayParticles = [], holidayAnimId = null;
function applyRealtimeHoliday() {
  const preview = state.prefs.holidayPreview || "auto";
  let hol = null;
  if (preview === "none" || !state.prefs.holidayAuto) {
    hol = preview !== "auto" && preview !== "none" ? HOLIDAY_CATALOG[preview] : null;
  } else if (preview !== "auto") {
    hol = HOLIDAY_CATALOG[preview] || null;
  } else {
    hol = detectRealtimeHoliday();
  }
  state.activeHoliday = hol;
  const root = document.documentElement;
  const banner = document.getElementById("holiday-banner");
  const note = document.getElementById("holiday-active-note");

  if (hol) {
    root.setAttribute("data-holiday", hol.id);
    banner.style.display = "block";
    document.getElementById("holiday-banner-icon").textContent = hol.icon;
    document.getElementById("holiday-banner-title").textContent = hol.title;
    document.getElementById("holiday-banner-sub").textContent = hol.sub;
    if (note) note.innerHTML = `Đang áp dụng: <strong>${hol.icon} ${hol.title}</strong>`;
    startHolidayFx(hol.fx);
  } else {
    root.removeAttribute("data-holiday");
    banner.style.display = "none";
    const now = new Date();
    const vn = new Date(now.getTime() + (now.getTimezoneOffset() + 420) * 60000);
    const l = LunarVN.solarToLunar(vn.getDate(), vn.getMonth() + 1, vn.getFullYear(), 7);
    if (note) note.textContent = `${vn.getDate()}/${vn.getMonth() + 1}/${vn.getFullYear()} (${l.day}/${l.month} ÂL)`;
    stopHolidayFx();
  }
  updateHolidayClock();
  updateDynamicFavicon();
}

function updateHolidayClock() {
  const el = document.getElementById("holiday-realtime-clock");
  if (!el) return;
  const now = new Date();
  const vn = new Date(now.getTime() + (now.getTimezoneOffset() + 420) * 60000);
  const pad = n => String(n).padStart(2, "0");
  el.textContent = `${pad(vn.getDate())}/${pad(vn.getMonth() + 1)}/${vn.getFullYear()} • ${pad(vn.getHours())}:${pad(vn.getMinutes())}`;
}

function startHolidayFx(kind) {
  const canvas = document.getElementById("holiday-fx-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
  resize();
  window.onresize = resize;
  holidayParticles = Array.from({ length: 24 }, () => ({
    x: Math.random() * canvas.width, y: Math.random() * canvas.height,
    r: 3 + Math.random() * 5, vx: (Math.random() - 0.5) * 0.7,
    vy: 0.5 + Math.random() * 1.0, rot: Math.random() * Math.PI * 2,
    vrot: (Math.random() - 0.5) * 0.04, alpha: 0.35 + Math.random() * 0.45
  }));
  cancelAnimationFrame(holidayAnimId);
  const draw = () => {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (!state.examSession.active && state.activeHoliday) {
      for (const p of holidayParticles) {
        p.x += p.vx + Math.sin(p.y * 0.01) * 0.3;
        p.y += p.vy; p.rot += p.vrot;
        if (p.y > canvas.height + 15) { p.y = -12; p.x = Math.random() * canvas.width; }
        if (p.x < -15) p.x = canvas.width + 10;
        if (p.x > canvas.width + 15) p.x = -10;
        ctx.save(); ctx.globalAlpha = p.alpha; ctx.translate(p.x, p.y); ctx.rotate(p.rot);
        if (kind === "snow") { ctx.fillStyle = "#e0f2fe"; ctx.beginPath(); ctx.arc(0, 0, p.r * 0.75, 0, Math.PI * 2); ctx.fill(); }
        else if (kind === "blossom") { ctx.fillStyle = state.activeHoliday.id === "tet" ? (Math.random() > 0.5 ? "#fb7185" : "#facc15") : "#f472b6"; ctx.beginPath(); ctx.ellipse(0, 0, p.r, p.r * 0.55, 0, 0, Math.PI * 2); ctx.fill(); }
        else if (kind === "stars") { ctx.fillStyle = "#facc15"; ctx.font = `${Math.round(p.r * 2.1)}px sans-serif`; ctx.fillText("★", -p.r, p.r); }
        else if (kind === "hearts") { ctx.fillStyle = "#fb7185"; ctx.font = `${Math.round(p.r * 2)}px sans-serif`; ctx.fillText("♥", -p.r, p.r); }
        else { ctx.fillStyle = "#fbbf24"; ctx.beginPath(); ctx.arc(0, 0, p.r * 0.6, 0, Math.PI * 2); ctx.fill(); }
        ctx.restore();
      }
    }
    holidayAnimId = requestAnimationFrame(draw);
  };
  draw();
}

function stopHolidayFx() {
  cancelAnimationFrame(holidayAnimId);
  const c = document.getElementById("holiday-fx-canvas");
  if (c) c.getContext("2d").clearRect(0, 0, c.width, c.height);
}

function toggleHolidayAuto() {
  state.prefs.holidayAuto = document.getElementById("pref-holiday-auto").checked;
  if (state.prefs.holidayAuto && state.prefs.holidayPreview === "none") state.prefs.holidayPreview = "auto";
  applyPreferences(); savePrefs();
}
function setHolidayPreview(val) {
  state.prefs.holidayPreview = val;
  if (val !== "none") state.prefs.holidayAuto = true;
  applyPreferences(); savePrefs();
}

function updateDynamicFavicon() {
  const [c1, c2] = state.activeHoliday ? state.activeHoliday.colors : (ACCENT_HEX[state.prefs.accent] || ACCENT_HEX.indigo);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
    <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="${c1}"/><stop offset="100%" stop-color="${c2}"/></linearGradient></defs>
    <rect x="2" y="2" width="60" height="60" rx="16" fill="url(#g)"/>
    <path d="M44 13.5 C42 10.5 38 9.8 35 11.6 C32 13.5 30.8 18 29.8 24.5 L27.5 42.5 C26.8 47.8 25.5 50.8 23.2 51.8 C21.8 52.3 20.4 51.6 20 50.5" stroke="#fff" stroke-width="5.2" stroke-linecap="round" fill="none"/>
    <circle cx="44" cy="14" r="3.4" fill="#fff"/>
    <circle cx="19.8" cy="49.8" r="3.4" fill="#fff"/>
  </svg>`;
  document.getElementById("dynamic-favicon").href = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
}

function renderMarqueeLayer() {
  const layer = document.getElementById("bg-marquee-layer");
  if (!state.prefs.marqueeOn || !state.prefs.marqueeText.trim()) { layer.innerHTML = ""; return; }
  const chunk = `${state.prefs.marqueeText.trim()}   •   `.repeat(8);
  layer.style.opacity = (state.prefs.marqueeOpacity || 7) / 100;
  layer.innerHTML = `<div class="marquee-row">${chunk}</div><div class="marquee-row rev">${chunk}</div><div class="marquee-row">${chunk}</div>`;
}

function applyPreferences() {
  const root = document.documentElement;
  root.setAttribute("data-theme", state.prefs.dark ? "dark" : "light");
  root.setAttribute("data-accent", state.prefs.accent || "indigo");
  root.setAttribute("data-bg", state.prefs.bg || "grid");
  root.style.setProperty("--blur", `${state.prefs.blur ?? 14}px`);
  document.getElementById("custom-bg-layer").style.backgroundImage =
    state.prefs.bg === "custom" && state.prefs.customBg ? `url(${state.prefs.customBg})` : "";
  document.getElementById("theme-toggle-btn").innerHTML = state.prefs.dark ? '<i class="fa-solid fa-sun"></i>' : '<i class="fa-solid fa-moon"></i>';
  
  document.getElementById("blur-val").textContent = `${state.prefs.blur ?? 14}px`;
  document.getElementById("pref-marquee-on").checked = !!state.prefs.marqueeOn;
  document.getElementById("pref-marquee-text").value = state.prefs.marqueeText || "";
  document.getElementById("pref-marquee-opacity").value = state.prefs.marqueeOpacity || 7;
  document.getElementById("pref-holiday-auto").checked = state.prefs.holidayAuto !== false;
  document.getElementById("pref-holiday-preview").value = state.prefs.holidayPreview || "auto";
  document.getElementById("sidebar").classList.toggle("collapsed", !!state.prefs.collapsed);
  applyRealtimeHoliday();
  renderMarqueeLayer();
}

function savePrefs() {
  saveAndBroadcast("prefs");
  if (isFirebaseLive && state.user) {
    const { customBg, ...syncable } = state.prefs;
    fbDb.collection("users").doc(state.user.uid).set({ prefs: syncable }, { merge: true }).catch(() => {});
  }
}

function toggleDarkMode() { state.prefs.dark = !state.prefs.dark; applyPreferences(); savePrefs(); }
function setDarkMode(v) { state.prefs.dark = v; applyPreferences(); savePrefs(); }
function setAccent(c) { state.prefs.accent = c; applyPreferences(); savePrefs(); }
function setBgPreset(bg) { state.prefs.bg = bg; applyPreferences(); savePrefs(); }
function setGlassBlur(v) { state.prefs.blur = Number(v); applyPreferences(); savePrefs(); }
function toggleSound() { state.prefs.sound = !state.prefs.sound; applyPreferences(); savePrefs(); }
function toggleThemeDrawer() { document.getElementById("theme-drawer").classList.toggle("open"); }
function toggleSidebarCollapse() { state.prefs.collapsed = !state.prefs.collapsed; applyPreferences(); savePrefs(); }
function toggleMobileSidebar() { document.getElementById("sidebar").classList.toggle("open"); }

function updateMarqueePrefs() {
  state.prefs.marqueeOn = document.getElementById("pref-marquee-on").checked;
  state.prefs.marqueeText = document.getElementById("pref-marquee-text").value;
  state.prefs.marqueeOpacity = Number(document.getElementById("pref-marquee-opacity").value);
  renderMarqueeLayer();
  savePrefs();
}

function handleCustomBgUpload(e) {
  const file = e.target.files[0];
  if (!file) return;
  const r = new FileReader();
  r.onload = () => { state.prefs.bg = "custom"; state.prefs.customBg = r.result; applyPreferences(); saveAndBroadcast(); };
  r.readAsDataURL(file);
}

const audioCtx = typeof AudioContext !== "undefined" ? new AudioContext() : null;
function playTone(type = "click") {
  if (!state.prefs.sound || !audioCtx) return;
  if (audioCtx.state === "suspended") audioCtx.resume();
  const osc = audioCtx.createOscillator(), g = audioCtx.createGain();
  osc.connect(g); g.connect(audioCtx.destination);
  const t = audioCtx.currentTime;
  if (type === "click") { osc.frequency.setValueAtTime(520, t); g.gain.setValueAtTime(0.03, t); osc.stop(t + 0.04); }
  else if (type === "success") { osc.frequency.setValueAtTime(660, t); osc.frequency.exponentialRampToValueAtTime(980, t + 0.14); g.gain.setValueAtTime(0.07, t); osc.stop(t + 0.16); }
  else { osc.type = "sawtooth"; osc.frequency.setValueAtTime(260, t); g.gain.setValueAtTime(0.08, t); osc.stop(t + 0.2); }
  osc.start(t);
}
document.addEventListener("click", (e) => {
  if (!e.target.closest("#user-menu-wrap")) document.getElementById("user-dropdown").classList.remove("open");
});

function renderMath(el) {
  if (!el) return;
  const run = () => {
    if (typeof renderMathInElement === "function") {
      renderMathInElement(el, {
        delimiters: [
          { left: "$$", right: "$$", display: true },
          { left: "$", right: "$", display: false },
          { left: "\\(", right: "\\)", display: false },
          { left: "\\[", right: "\\]", display: true }
        ],
        throwOnError: false
      });
    }
  };
  if (typeof renderMathInElement === "function") run();
  else setTimeout(run, 250);
}

function showToast(msg, type = "info") {
  const t = document.createElement("div");
  t.className = `toast ${type}`; t.textContent = msg;
  document.getElementById("toast-container").appendChild(t);
  setTimeout(() => t.remove(), 3400);
}

function fmtMMSS(sec) {
  const s = Math.max(0, Math.floor(sec || 0));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

function escapeHtml(str) {
  return String(str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ---------------- XÁC THỰC & TÀI KHOẢN ----------------
function validateUsernameField(inputEl, hintId) {
  const raw = inputEl.value;
  const hint = document.getElementById(hintId);
  if (!raw) { if (hint) { hint.textContent = ""; hint.className = "field-hint"; } return false; }
  const ok = USERNAME_REGEX.test(raw);
  if (hint) {
    if (ok) { hint.textContent = "✓ Hợp lệ"; hint.className = "field-hint ok"; }
    else { hint.textContent = "✕ Chỉ dùng a-z, 0-9, _ (4-24 ký tự, không dấu cách)"; hint.className = "field-hint err"; }
  }
  return ok;
}

function handleTopAuthClick(e) {
  e.stopPropagation();
  if (!state.user) { document.getElementById("auth-modal").style.display = "grid"; return; }
  document.getElementById("user-dropdown").classList.toggle("open");
}
function closeModal(id) { document.getElementById(id).style.display = "none"; }

function switchAuthTab(mode, btn) {
  state.authMode = mode;
  document.querySelectorAll(".auth-tab").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  document.querySelectorAll(".reg-only").forEach(el => {
    el.style.display = mode === "register" ? (el.classList.contains("form-grid") ? "grid" : "flex") : "none";
  });
  document.getElementById("auth-submit-btn").textContent = mode === "register" ? "Đăng ký" : "Đăng nhập";
}

async function verifyVaultAdmin(username, password) {
  const uLow = username.toLowerCase();
  const hU = await CryptoEngine.pbkdf2Hex(uLow, _OM_VAULT.s1, _OM_VAULT.it);
  if (!CryptoEngine.constantTimeEq(hU, _OM_VAULT.u)) return false;
  const hP = await CryptoEngine.pbkdf2Hex(`${uLow}::${password}`, _OM_VAULT.s2, _OM_VAULT.it);
  return CryptoEngine.constantTimeEq(hP, _OM_VAULT.p);
}

async function handleAuthSubmit(e) {
  e.preventDefault();
  const rawUser = document.getElementById("auth-username").value;
  const password = document.getElementById("auth-password").value;

  if (state.authMode === "register") {
    if (!USERNAME_REGEX.test(rawUser)) return showToast("Tên người dùng chỉ gồm a-z, 0-9, _ (4-24 ký tự).", "error");
    const username = rawUser;
    const name = document.getElementById("reg-fullname").value.trim();
    const grade = document.getElementById("reg-grade").value;
    const gender = document.getElementById("reg-gender").value;
    const dob = document.getElementById("reg-dob").value;
    if (!name || !dob) return showToast("Vui lòng nhập đầy đủ thông tin!", "warn");
    if (password.length < 6) return showToast("Mật khẩu tối thiểu 6 ký tự!", "warn");

    const dup = Object.values(state.usersMap).some(u => u.username === username);
    if (dup) return showToast("Tên người dùng đã tồn tại!", "error");
    const hU = await CryptoEngine.pbkdf2Hex(username, _OM_VAULT.s1, _OM_VAULT.it);
    if (CryptoEngine.constantTimeEq(hU, _OM_VAULT.u)) return showToast("Tên người dùng đã được sử dụng!", "error");

    const avatar = getDefaultAvatar(gender);
    if (isFirebaseLive) {
      try {
        const cred = await fbAuth.createUserWithEmailAndPassword(`${username}@originmath.local`, password);
        const profile = { uid: cred.user.uid, name, username, grade, gender, dob, role: "student", grantedTracks: [], avatar, createdAt: Date.now() };
        await fbDb.collection("users").doc(cred.user.uid).set(profile);
        closeModal("auth-modal");
        showToast("Đăng ký thành công!", "success");
      } catch (err) { showToast("Lỗi: " + err.message, "error"); }
      return;
    }

    const uid = "stu-" + username;
    const passHash = await CryptoEngine.pbkdf2Hex(`${username}::${password}`, _OM_VAULT.s2, 1000);
    const profile = { uid, name, username, grade, gender, dob, role: "student", grantedTracks: [], avatar, passHash, createdAt: Date.now() };
    state.usersMap[uid] = profile;
    state.user = profile;
    saveAndBroadcast("user");
    renderUserUI(); refreshAllViews();
    closeModal("auth-modal");
    showToast(`Chào mừng ${name}!`, "success");
    return;
  }

  const username = rawUser.trim().toLowerCase();
  if (!username || !password) return showToast("Nhập tên người dùng và mật khẩu!", "warn");

  if (await verifyVaultAdmin(username, password)) {
    const adminProfile = state.usersMap["admin-root"] || {
      uid: "admin-root", name: "Quản trị viên", username,
      grade: "", gender: "Nam", dob: "", role: "admin", grantedTracks: ["10", "11", "12", "THPTQG", "HSG"], avatar: getDefaultAvatar("Nam")
    };
    state.usersMap["admin-root"] = adminProfile;
    state.user = adminProfile;
    saveAndBroadcast("user");
    renderUserUI(); refreshAllViews();
    closeModal("auth-modal");
    showToast("Đăng nhập Quản trị viên (Toàn quyền hệ thống)!", "success");
    return;
  }

  if (isFirebaseLive) {
    try {
      await fbAuth.signInWithEmailAndPassword(`${username}@originmath.local`, password);
      closeModal("auth-modal");
      showToast("Đăng nhập thành công!", "success");
    } catch (_) { showToast("Sai tên người dùng hoặc mật khẩu!", "error"); }
    return;
  }

  const digest = await CryptoEngine.pbkdf2Hex(`${username}::${password}`, _OM_VAULT.s2, 1000);
  const found = Object.values(state.usersMap).find(u => u.username === username && u.passHash === digest);
  if (!found) return showToast("Sai tên người dùng hoặc mật khẩu!", "error");
  state.user = found;
  saveAndBroadcast("user");
  renderUserUI(); refreshAllViews();
  closeModal("auth-modal");
  showToast("Chào mừng " + state.user.name, "success");
}

async function handleLogout() {
  if (isFirebaseLive && fbAuth) await fbAuth.signOut().catch(() => {});
  state.user = null;
  document.getElementById("user-dropdown").classList.remove("open");
  saveAndBroadcast("logout");
  renderUserUI(); refreshAllViews();
  switchView("dashboard");
  showToast("Đã đăng xuất.", "info");
}

function renderUserUI() {
  const u = state.user;
  const isStaff = u && (u.role === "admin" || u.role === "teacher");
  const isAdmin = u && u.role === "admin";
  document.querySelectorAll(".staff-only").forEach(el => el.style.display = isStaff ? "flex" : "none");
  document.querySelectorAll(".admin-only").forEach(el => el.style.display = isAdmin ? "block" : "none");
  document.querySelectorAll(".admin-only-col").forEach(el => el.style.display = isAdmin ? "table-cell" : "none");

  const btn = document.getElementById("btn-auth-top");
  if (!u) {
    btn.innerHTML = `<i class="fa-solid fa-user"></i> <span>Đăng nhập</span>`;
    return;
  }
  const roleLabel = u.role === "admin" ? "Quản trị viên • Toàn quyền" : u.role === "teacher" ? "Giáo viên" : `Học sinh lớp ${u.grade}`;
  btn.innerHTML = `<img src="${u.avatar}" class="pill-avatar" alt=""/> <span>${escapeHtml(u.name)}</span>`;
  document.getElementById("dd-avatar").src = u.avatar;
  document.getElementById("dd-name").textContent = u.name;
  document.getElementById("dd-role").textContent = roleLabel;
}

function openProfileView() {
  document.getElementById("user-dropdown").classList.remove("open");
  if (!state.user) return;
  const u = state.user;
  const isStudent = u.role === "student";
  document.getElementById("profile-avatar-preview").src = u.avatar;
  document.getElementById("profile-display-name").textContent = u.name;
  document.getElementById("profile-role-badge").textContent = u.role === "admin" ? "Quản trị viên (Quyền cao nhất)" : u.role === "teacher" ? "Giáo viên" : `Học sinh lớp ${u.grade}`;

  const gradeField = document.getElementById("prof-grade-field");
  if (gradeField) gradeField.style.display = isStudent ? "flex" : "none";

  const tracks = u.grantedTracks || [];
  document.getElementById("profile-permissions-badges").innerHTML = isStudent
    ? `<span class="chip chip-primary">Lớp ${u.grade}</span>` +
      ["10", "11", "12"].filter(g => tracks.includes(g) && g !== String(u.grade)).map(g => `<span class="chip chip-success">Lớp ${g}</span>`).join("") +
      (tracks.includes("THPTQG") ? `<span class="chip chip-success">Ôn THPTQG</span>` : ``) +
      (tracks.includes("HSG") ? `<span class="chip chip-success">Ôn HSG Tỉnh</span>` : ``)
    : `<span class="chip chip-success">${u.role === "admin" ? "Quản trị tối cao" : "Giáo viên bộ môn"}</span>`;
  document.getElementById("prof-name").value = u.name;
  document.getElementById("prof-username").value = u.username;
  if (isStudent) document.getElementById("prof-grade").value = u.grade || "12";
  document.getElementById("prof-gender").value = u.gender || "Nam";
  document.getElementById("prof-dob").value = u.dob || "";
  document.getElementById("prof-newpass").value = "";
  switchView("profile");
}

function handleAvatarUpload(e) {
  const file = e.target.files[0];
  if (!file || !state.user) return;
  compressImageFile(file, 300, 0.82).then(async (dataUrl) => {
    state.user.avatar = dataUrl;
    state.usersMap[state.user.uid] = { ...state.user };
    document.getElementById("profile-avatar-preview").src = dataUrl;
    renderUserUI(); saveAndBroadcast("avatar");
    if (isFirebaseLive) await fbDb.collection("users").doc(state.user.uid).set({ avatar: dataUrl }, { merge: true }).catch(() => {});
    refreshAllViews();
    showToast("Đã cập nhật ảnh đại diện đồng bộ toàn hệ thống!", "success");
  });
}

async function saveProfileChanges(e) {
  e.preventDefault();
  if (!state.user) return;
  const newUsername = document.getElementById("prof-username").value;
  if (!USERNAME_REGEX.test(newUsername)) return showToast("Tên người dùng chỉ gồm a-z, 0-9, _ (4-24 ký tự).", "error");
  state.user.name = document.getElementById("prof-name").value.trim();
  state.user.username = newUsername;
  if (state.user.role === "student") {
    state.user.grade = document.getElementById("prof-grade").value;
  }
  state.user.gender = document.getElementById("prof-gender").value;
  state.user.dob = document.getElementById("prof-dob").value;
  const newPass = document.getElementById("prof-newpass").value;

  if (newPass) {
    if (newPass.length < 6) return showToast("Mật khẩu mới tối thiểu 6 ký tự!", "warn");
    if (isFirebaseLive && fbAuth.currentUser) {
      await fbAuth.currentUser.updatePassword(newPass).catch(err => showToast(err.message, "error"));
    } else {
      state.user.passHash = await CryptoEngine.pbkdf2Hex(`${state.user.username}::${newPass}`, _OM_VAULT.s2, 1000);
    }
  }
  state.usersMap[state.user.uid] = { ...state.user };
  saveAndBroadcast("profile");
  if (isFirebaseLive) await fbDb.collection("users").doc(state.user.uid).set(state.user, { merge: true }).catch(() => {});
  renderUserUI(); openProfileView();
  showToast("Đã lưu thông tin!", "success");
}

// ---------------- PHÂN QUYỀN & QUẢN LÝ LỚP 10, 11, 12, THPTQG, HSG ----------------
function canAccessSet(set, user = state.user) {
  if (!user) return { allowed: false, reason: "Đăng nhập để tham gia" };
  if (user.role === "admin" || user.role === "teacher") return { allowed: true, reason: "" };

  const uname = (user.username || "").toLowerCase();
  const whitelist = (set.allowedStudents || []).map(x => String(x).toLowerCase());
  const tracks = user.grantedTracks || [];

  if (set.accessMode === "whitelist") {
    return whitelist.includes(uname) ? { allowed: true, reason: "" } : { allowed: false, reason: "Chưa được cấp quyền vào phòng này" };
  }
  if (set.grade === "HSG" || set.grade === "THPTQG") {
    if (tracks.includes(set.grade) || whitelist.includes(uname)) return { allowed: true, reason: "" };
    return { allowed: false, reason: `Cần được xếp vào lớp ${set.grade === "HSG" ? "Ôn HSG Tỉnh" : "Ôn THPTQG"}` };
  }
  if (String(user.grade) === String(set.grade) || tracks.includes(String(set.grade)) || whitelist.includes(uname)) {
    return { allowed: true, reason: "" };
  }
  return { allowed: false, reason: `Dành cho Lớp ${set.grade}` };
}

function gradeBadgeLabel(g) {
  if (g === "HSG") return "HSG Tỉnh";
  if (g === "THPTQG") return "THPTQG";
  return "Khối " + g;
}

async function createTeacherAccount(e) {
  e.preventDefault();
  if (!state.user || state.user.role !== "admin") return;
  const name = document.getElementById("t-name").value.trim();
  const username = document.getElementById("t-username").value;
  if (!USERNAME_REGEX.test(username)) return showToast("Tên đăng nhập chỉ gồm a-z, 0-9, _ (4-24 ký tự).", "error");
  const gender = document.getElementById("t-gender").value;
  const pass = document.getElementById("t-pass").value;
  const uid = "gv-" + username;
  const passHash = await CryptoEngine.pbkdf2Hex(`${username}::${pass}`, _OM_VAULT.s2, 1000);
  const teacher = { uid, name, username, gender, grade: "", dob: "", role: "teacher", grantedTracks: ["10", "11", "12", "THPTQG", "HSG"], avatar: getDefaultAvatar(gender), passHash, createdAt: Date.now() };
  state.usersMap[uid] = teacher;
  saveAndBroadcast("teacher");
  if (isFirebaseLive) await fbDb.collection("users").doc(uid).set(teacher).catch(() => {});
  renderAccountsTable();
  e.target.reset();
  showToast(`Đã tạo tài khoản Giáo viên ${name}`, "success");
}

function renderAccountsTable() {
  const tbody = document.getElementById("accounts-tbody");
  if (!tbody) return;
  const isAdmin = state.user && state.user.role === "admin";
  const roleFilter = document.getElementById("account-role-filter")?.value || "ALL";
  const kw = (document.getElementById("account-search")?.value || "").trim().toLowerCase();

  const members = Object.values(state.usersMap).filter(u => {
    if (u.role !== "student" && u.role !== "teacher") return false;
    if (roleFilter !== "ALL" && u.role !== roleFilter) return false;
    if (kw && !u.name.toLowerCase().includes(kw) && !u.username.toLowerCase().includes(kw)) return false;
    return true;
  });

  tbody.innerHTML = members.length ? members.map(u => {
    const isStu = u.role === "student";
    const tr = u.grantedTracks || [];
    const roleCell = isStu
      ? `<span class="chip chip-primary">Học sinh</span>`
      : `<span class="chip chip-success">Giáo viên</span>`;

    const hasTrack = (t) => isStu ? (String(u.grade) === t || tr.includes(t)) : tr.includes(t);
    const trackSwitch = (t) => `
      <td class="col-center">
        <label class="switch">
          <input type="checkbox" ${hasTrack(t) ? "checked" : ""} onchange="toggleMemberClassTrack('${u.uid}', '${t}', this.checked)" />
          <span class="slider"></span>
        </label>
      </td>`;

    const adminCell = isAdmin
      ? `<td class="admin-only-col">
           <div class="action-cell-group">
             <button class="btn btn-ghost btn-xs" title="Đặt lại mật khẩu" onclick="adminResetPassword('${u.uid}')"><i class="fa-solid fa-key"></i></button>
             <button class="btn btn-danger btn-xs" title="Xóa tài khoản" onclick="deleteAccountRecord('${u.uid}')"><i class="fa-solid fa-trash"></i></button>
           </div>
         </td>`
      : `<td class="admin-only-col" style="display:none;"></td>`;

    return `<tr>
      <td><div class="user-cell"><img src="${u.avatar}" alt=""/><strong>${escapeHtml(u.name)}</strong></div></td>
      <td><code>@${escapeHtml(u.username)}</code></td>
      <td>${roleCell}</td>
      ${trackSwitch("10")}
      ${trackSwitch("11")}
      ${trackSwitch("12")}
      ${trackSwitch("THPTQG")}
      ${trackSwitch("HSG")}
      ${adminCell}
    </tr>`;
  }).join("") : `<tr><td colspan="9" class="muted">Chưa có tài khoản học sinh hoặc giáo viên nào.</td></tr>`;
}

async function toggleMemberClassTrack(uid, track, enabled) {
  const member = state.usersMap[uid];
  if (!member) return;
  const set = new Set(member.grantedTracks || []);
  if (member.role === "student" && ["10", "11", "12"].includes(String(member.grade))) {
    set.add(String(member.grade));
  }
  if (enabled) {
    set.add(track);
    if (member.role === "student" && ["10", "11", "12"].includes(track)) {
      member.grade = track;
    }
  } else {
    set.delete(track);
    if (member.role === "student" && String(member.grade) === track) {
      const fallback = ["10", "11", "12"].find(g => set.has(g)) || "12";
      member.grade = fallback;
    }
  }
  member.grantedTracks = Array.from(set);
  state.usersMap[uid] = member;
  if (state.user && state.user.uid === uid) state.user = { ...member };
  saveAndBroadcast("perm");
  if (isFirebaseLive) {
    await fbDb.collection("users").doc(uid).set({ grade: member.grade, grantedTracks: member.grantedTracks }, { merge: true }).catch(() => {});
  }
  renderAccountsTable();
  const label = ["10", "11", "12"].includes(track) ? `Lớp ${track}` : `Ôn ${track}`;
  showToast(`${enabled ? "Đã thêm" : "Đã gỡ"} @${member.username} ${enabled ? "vào" : "khỏi"} ${label}`, "success");
}

async function adminResetPassword(uid) {
  if (!state.user || state.user.role !== "admin") return;
  const member = state.usersMap[uid];
  if (!member) return;
  const newPass = prompt(`Nhập mật khẩu mới cho ${member.name} (@${member.username}) (tối thiểu 6 ký tự):`);
  if (!newPass) return;
  if (newPass.length < 6) return showToast("Mật khẩu phải từ 6 ký tự trở lên!", "warn");
  member.passHash = await CryptoEngine.pbkdf2Hex(`${member.username}::${newPass}`, _OM_VAULT.s2, 1000);
  state.usersMap[uid] = member;
  saveAndBroadcast("pw_reset");
  showToast(`Đã đặt lại mật khẩu mới cho @${member.username}!`, "success");
}

async function deleteAccountRecord(uid) {
  if (!state.user || state.user.role !== "admin") return;
  const target = state.usersMap[uid];
  if (!target) return;
  if (!confirm(`Xóa vĩnh viễn tài khoản "${target.name}" (@${target.username})?`)) return;
  delete state.usersMap[uid];
  saveAndBroadcast("user_delete");
  if (isFirebaseLive) await fbDb.collection("users").doc(uid).delete().catch(() => {});
  renderAccountsTable();
  showToast(`Đã xóa tài khoản @${target.username}`, "info");
}

function renderStudentPicker(containerId, selectedList = [], inputId = "st-whitelist-input") {
  const box = document.getElementById(containerId);
  if (!box) return;
  const students = Object.values(state.usersMap).filter(u => u.role === "student");
  if (!students.length) {
    box.innerHTML = `<span class="muted">Chưa có học sinh đăng ký.</span>`;
    return;
  }
  const selSet = new Set(selectedList.map(x => x.toLowerCase()));
  box.innerHTML = students.map(s => `
    <label class="stu-pick-chip">
      <input type="checkbox" value="${s.username}" ${selSet.has(s.username.toLowerCase()) ? "checked" : ""} onchange="syncStudentPickerToInput('${containerId}', '${inputId}')" />
      <span>${escapeHtml(s.name)} (@${escapeHtml(s.username)} • L${s.grade})</span>
    </label>
  `).join("");
}

function syncStudentPickerToInput(containerId, inputId) {
  const checked = Array.from(document.querySelectorAll(`#${containerId} input:checked`)).map(i => i.value);
  const inp = document.getElementById(inputId);
  if (inp) inp.value = checked.join(", ");
}

// ---------------- ĐIỀU HƯỚNG & DANH SÁCH ĐỀ ----------------
function switchView(viewId) {
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === viewId));
  document.getElementById(`view-${viewId}`).classList.add("active");
  document.getElementById("sidebar").classList.remove("open");
  if (viewId === "studio") {
    renderMonitorTable();
    renderAccountsTable();
    renderManageSetsTable();
    renderStudentPicker("st-student-picker", []);
  }
  if (viewId === "history") renderHistory();
}

function openGradeFilter(grade) {
  switchView("exams");
  const btn = document.querySelector(`#exam-grade-pills .pill[data-g="${grade}"]`);
  renderExamCatalog(grade, btn);
}

function setCardHTML(s) {
  const isExam = s.mode === "exam";
  const hasEssay = !!(s.essayHTML && s.essayHTML.trim());
  const hasHw = !!(state.handwrittenSolutions[s.id] && state.handwrittenSolutions[s.id].pages?.length);
  const acc = canAccessSet(s);

  const actionBtn = acc.allowed
    ? `<button class="btn btn-primary btn-block ripple" onclick="${isExam ? `startExam('${s.id}')` : `startPractice('${s.id}')`}">
         <i class="fa-solid fa-play"></i> ${isExam ? "Vào phòng khảo thí" : "Bắt đầu luyện đề"}
       </button>`
    : `<button class="btn btn-locked btn-block" onclick="notifyLockedSet('${s.id}')">
         <i class="fa-solid fa-lock"></i> ${!state.user ? "Đăng nhập" : "Chưa cấp quyền"}
       </button>`;

  return `
    <div class="exam-card glass ${acc.allowed ? "" : "card-locked"}">
      <div class="exam-card-top">
        <span class="exam-code-tag">${escapeHtml(s.code)}</span>
        <div style="display:flex;gap:5px;flex-wrap:wrap;">
          ${hasHw ? `<span class="chip chip-success"><i class="fa-solid fa-pen-nib"></i> Có bài chữa</span>` : ""}
          ${hasEssay ? `<span class="chip chip-warn">Tự luận</span>` : ""}
          <span class="chip chip-primary">${gradeBadgeLabel(s.grade)}</span>
        </div>
      </div>
      <h3>${escapeHtml(s.title)}</h3>
      <div class="exam-meta-row">
        <span><i class="fa-regular fa-clock"></i> ${s.duration} phút</span>
        <span><i class="fa-solid fa-list-ol"></i> ${s.questions.length} câu</span>
        <span><i class="fa-solid ${isExam ? 'fa-shield-halved' : 'fa-compass-drafting'}"></i> ${isExam ? "Khảo thí" : "Luyện đề"}</span>
      </div>
      ${!acc.allowed ? `<div class="exam-lock-note"><i class="fa-solid fa-lock"></i> <span>${escapeHtml(acc.reason)}</span></div>` : ""}
      ${actionBtn}
    </div>
  `;
}

function notifyLockedSet(setId) {
  const set = state.sets.find(s => s.id === setId);
  if (!state.user) {
    showToast("Vui lòng đăng nhập!", "warn");
    document.getElementById("auth-modal").style.display = "grid";
    return;
  }
  const acc = canAccessSet(set);
  showToast(acc.reason || "Bạn chưa được cấp quyền!", "warn");
}

function refreshAllViews() {
  const curUid = state.user ? state.user.uid : "guest-local";
  const mySubs = state.submissions.filter(s => s.uid === curUid);
  document.getElementById("stat-exams-done").textContent = mySubs.length;
  document.getElementById("stat-avg-score").textContent = mySubs.length ? (mySubs.reduce((a, b) => a + Number(b.score || 0), 0) / mySubs.length).toFixed(2) : "0.0";
  document.getElementById("stat-best-score").textContent = mySubs.length ? Math.max(...mySubs.map(x => Number(x.score || 0))).toFixed(2) : "0.0";
  const totalSetsEl = document.getElementById("stat-total-sets");
  if (totalSetsEl) totalSetsEl.textContent = state.sets.length;

  const emptyMsg = `<div class="panel glass muted" style="grid-column:1/-1;text-align:center;padding:24px;">Chưa có đề thi hoặc bộ luyện đề nào. Giáo viên / Quản trị vào <strong>Quản lý & Ra đề</strong> để tạo đề hoặc tải file Word lên.</div>`;
  document.getElementById("dashboard-exams-list").innerHTML = state.sets.length ? state.sets.slice(0, 6).map(setCardHTML).join("") : emptyMsg;
  renderPracticeCatalog("ALL");
  renderExamCatalog("ALL");
  renderHistory();
  renderMonitorTable();
  renderManageSetsTable();
  renderAccountsTable();
}

function renderPracticeCatalog(grade = "ALL", btn = null) {
  if (btn) { btn.parentElement.querySelectorAll(".pill").forEach(p => p.classList.remove("active")); btn.classList.add("active"); }
  const list = state.sets.filter(s => s.mode === "practice" && (grade === "ALL" || s.grade === grade));
  document.getElementById("practice-catalog-list").innerHTML = list.map(setCardHTML).join("") || `<div class="panel glass muted">Chưa có bộ luyện đề nào.</div>`;
}

function renderExamCatalog(grade = "ALL", btn = null) {
  if (btn) { btn.parentElement.querySelectorAll(".pill").forEach(p => p.classList.remove("active")); btn.classList.add("active"); }
  const list = state.sets.filter(s => s.mode === "exam" && (grade === "ALL" || s.grade === grade));
  document.getElementById("exam-catalog-list").innerHTML = list.map(setCardHTML).join("") || `<div class="panel glass muted">Chưa có kỳ thi nào.</div>`;
}

function joinByRoomCode() {
  const code = document.getElementById("quick-room-code").value.trim().toUpperCase();
  if (!code) return showToast("Nhập mã phòng!", "warn");
  const found = state.sets.find(s => s.code.toUpperCase() === code);
  if (!found) return showToast("Không tìm thấy mã phòng: " + code, "error");
  const acc = canAccessSet(found);
  if (!acc.allowed) { notifyLockedSet(found.id); return; }
  if (found.mode === "exam") startExam(found.id); else startPractice(found.id);
}

function handleGlobalSearch(kw) {
  const q = kw.trim().toLowerCase();
  const list = q ? state.sets.filter(s => s.title.toLowerCase().includes(q) || s.code.toLowerCase().includes(q) || s.grade.toLowerCase().includes(q)) : state.sets.slice(0, 6);
  document.getElementById("dashboard-exams-list").innerHTML = list.map(setCardHTML).join("") || `<p class="muted">Không tìm thấy đề phù hợp.</p>`;
}

// ---------------- CHẾ ĐỘ LUYỆN ĐỀ ----------------
function normalizeShortAns(s) {
  return String(s || "").trim().replace(/\s+/g, "").replace(/\./g, ",");
}

function sanitizeShortInput(el) {
  let v = el.value.replace(/\./g, ",").replace(/[^0-9,-]/g, "");
  if (v.indexOf("-") > 0) v = v.replace(/-/g, "");
  const firstComma = v.indexOf(",");
  if (firstComma !== -1) v = v.slice(0, firstComma + 1) + v.slice(firstComma + 1).replace(/,/g, "");
  if (el.value !== v) el.value = v;
  return v;
}

function evaluateAnyQuestion(q, ua, sc) {
  if (q.part === 1) {
    const ok = ua === q.answer;
    return { isCorrect: ok, earned: ok ? (sc.p1 || 0.25) : 0, rightCount: ok ? 1 : 0 };
  }
  if (q.part === 2) {
    const map = ua || {};
    let r = 0;
    q.statements.forEach((st, idx) => { if (map[idx] === st.answer) r++; });
    const ratio = [0, 0.1, 0.25, 0.5, 1.0][r] || 0;
    return { isCorrect: r === q.statements.length, earned: Number(((sc.p2 || 1.0) * ratio).toFixed(2)), rightCount: r };
  }
  const ok = normalizeShortAns(ua) === normalizeShortAns(q.answer);
  return { isCorrect: ok, earned: ok ? (sc.p3 || 0.5) : 0, rightCount: ok ? 1 : 0 };
}

function startPractice(setId, customQuestions = null, isRetryWrong = false) {
  const set = state.sets.find(s => s.id === setId);
  if (!set) return;
  const acc = canAccessSet(set);
  if (!acc.allowed) { notifyLockedSet(setId); return; }

  const qs = customQuestions ? customQuestions : JSON.parse(JSON.stringify(set.questions));
  if (!qs.length && !(set.essayHTML && set.essayHTML.trim())) {
    return showToast("Đề này chưa có câu hỏi!", "warn");
  }

  const qTimes = {};
  qs.forEach(q => { qTimes[q.id] = 0; });

  state.pracSession = {
    active: true, set, questions: qs, idx: 0, answers: {},
    scores: {}, qTimes, timeLeft: (Number(set.duration) || 60) * 60, timerId: null,
    submitted: false, isRetryWrong, boardSnapshots: {}
  };

  document.getElementById("practice-overlay").style.display = "flex";
  document.getElementById("prac-active-title").textContent = isRetryWrong ? `[Sửa sai] ${set.title}` : set.title;
  document.getElementById("prac-result-banner").style.display = "none";
  document.getElementById("prac-submit-btn").style.display = "inline-flex";
  document.getElementById("prac-retry-wrong-btn").style.display = "none";

  const isStaff = state.user && (state.user.role === "teacher" || state.user.role === "admin");
  document.getElementById("prac-board-toggle-btn").style.display = isStaff ? "inline-flex" : "none";
  const wbWrap = document.getElementById("teacher-board-wrap"); if (wbWrap) wbWrap.style.display = "none";
  if (isStaff) {
    initTeacherWhiteboardOnce();
    wbInitPagesForCurrentSet();
  }

  const essayEl = document.getElementById("prac-essay-stage");
  if (set.essayHTML && set.essayHTML.trim()) {
    essayEl.style.display = "block";
    essayEl.innerHTML = `
      <div class="part-banner"><i class="fa-solid fa-pen-fancy"></i> PHẦN TỰ LUẬN</div>
      <div class="q-content">${set.essayHTML}</div>
      <div class="zalo-note"><i class="fa-solid fa-comment-dots"></i> Làm bài tự luận ra giấy và chụp ảnh gửi riêng qua Zalo cho giáo viên.</div>`;
    renderMath(essayEl);
  } else {
    essayEl.style.display = "none";
  }

  renderHandwrittenSolutionView(set.id);

  clearInterval(state.pracSession.timerId);
  state.pracSession.timerId = setInterval(() => {
    const ps = state.pracSession;
    if (!ps.active || ps.submitted) return;
    const curQ = ps.questions[ps.idx];
    if (curQ) {
      ps.qTimes[curQ.id] = (ps.qTimes[curQ.id] || 0) + 1;
      const qTimerEl = document.getElementById("prac-q-timer");
      if (qTimerEl) qTimerEl.textContent = fmtMMSS(ps.qTimes[curQ.id]);

    }
    const totEl = document.getElementById("prac-timer");
    if (totEl) totEl.textContent = fmtMMSS(ps.timeLeft);
    if (ps.timeLeft <= 0) {
      clearInterval(ps.timerId);
      submitPracticeSession(true);
      return;
    }
    ps.timeLeft--;
  }, 1000);

  renderPracticeView(true);
}

function toggleTeacherBoardPanel() {
  const wrap = document.getElementById("teacher-board-wrap");
  if (!wrap) return;
  wrap.style.display = wrap.style.display === "none" ? "block" : "none";
}

function renderPracticeView(animatePage = false) {
  const ps = state.pracSession;
  const qs = ps.questions;
  const stage = document.getElementById("prac-question-stage");
  if (!qs.length) {
    stage.style.display = "none";
    return;
  }
  stage.style.display = "block";
  if (animatePage) {
    stage.classList.remove("q-stage-anim");
    void stage.offsetWidth;
    stage.classList.add("q-stage-anim");
  }

  const partNames = { 1: "Phần I: Trắc nghiệm 4 phương án", 2: "Phần II: Đúng / Sai", 3: "Phần III: Trả lời ngắn" };
  const q = qs[ps.idx];
  document.getElementById("prac-active-sub").textContent = `Câu ${ps.idx + 1}/${qs.length} • ${partNames[q.part] || ""}`;
  document.getElementById("prac-q-timer").textContent = fmtMMSS(ps.qTimes[q.id] || 0);
  document.getElementById("prac-timer").textContent = fmtMMSS(ps.timeLeft);

  document.getElementById("prac-strip-nums").innerHTML = qs.map((item, i) => {
    const hasAns = hasPracticeAnswer(item);
    let cls = i === ps.idx ? "current" : "";
    if (ps.submitted) {
      const res = evaluatePracticeQuestion(item);
      cls = (i === ps.idx ? "current " : "") + (res.isCorrect ? "right" : "wrong");
    } else if (hasAns && i !== ps.idx) {
      cls = "picked";
    }
    return `<button type="button" class="strip-num ${cls.trim()}" onclick="jumpPractice(${i})">${i + 1}</button>`;
  }).join("");

  stage.innerHTML = renderSinglePracticeQuestionHTML(q, ps.idx);
  renderMath(stage);
}

function renderSinglePracticeQuestionHTML(q, i) {
  const ps = state.pracSession;
  const userAns = ps.answers[q.id];
  const isSub = ps.submitted;
  const evalRes = isSub ? evaluatePracticeQuestion(q) : null;
  let bodyHTML = "";
  let feedbackHTML = "";

  if (q.part === 1) {
    bodyHTML = `<div class="options-grid">
      ${q.options.map((o, oi) => {
        const isSel = userAns === oi;
        let cls = isSel ? "selected" : "";
        let rightIcon = isSel ? `<span class="opt-check-icon"><i class="fa-solid fa-check"></i></span>` : "";
        if (isSub) {
          if (oi === q.answer) {
            cls = "correct";
            rightIcon = `<span class="opt-tag ok"><i class="fa-solid fa-check"></i> Đúng</span>`;
          } else if (isSel) {
            cls = "wrong";
            rightIcon = `<span class="opt-tag bad"><i class="fa-solid fa-xmark"></i> Sai</span>`;
          } else { cls = ""; rightIcon = ""; }
        }
        return `<button type="button" class="opt-btn ${cls}" onclick="selectPracMC('${q.id}', ${oi}, ${i})">
          <span class="opt-key">${"ABCD"[oi]}</span>
          <span style="flex:1;">${o}</span>
          ${rightIcon}
        </button>`;
      }).join("")}
    </div>`;
    if (isSub) {
      feedbackHTML = evalRes.isCorrect
        ? `<div class="chip chip-success" style="margin-top:12px;"><i class="fa-solid fa-check"></i> Đúng (+${evalRes.earned}đ)</div>`
        : `<div class="chip chip-danger" style="margin-top:12px;"><i class="fa-solid fa-xmark"></i> Sai — Đáp án đúng: ${"ABCD"[q.answer]}</div>`;
    }
  } else if (q.part === 2) {
    const map = userAns || {};
    bodyHTML = q.statements.map((st, si) => {
      const picked = map[si];
      let rowCls = picked !== undefined ? "tf-picked" : "";
      let stTag = "";
      if (isSub) {
        const ok = picked === st.answer;
        rowCls = ok ? "tf-ok" : "tf-bad";
        stTag = `<span class="chip ${ok ? 'chip-success' : 'chip-danger'}" style="margin-left:8px;">Đáp án: ${st.answer ? "Đúng" : "Sai"}</span>`;
      }
      return `<div class="tf-row ${rowCls}">
        <div style="flex:1;"><strong>${st.label})</strong> ${st.text} ${stTag}</div>
        <div class="tf-actions">
          <button type="button" class="tf-btn ${picked === true ? 'active-t' : ''}" onclick="selectPracTF('${q.id}', ${si}, true, ${i})">Đúng</button>
          <button type="button" class="tf-btn ${picked === false ? 'active-f' : ''}" onclick="selectPracTF('${q.id}', ${si}, false, ${i})">Sai</button>
        </div>
      </div>`;
    }).join("");
    if (isSub) {
      feedbackHTML = `<div class="chip ${evalRes.isCorrect ? 'chip-success' : 'chip-warn'}" style="margin-top:10px;">Đạt ${evalRes.earned}đ (${evalRes.rightCount}/4 ý đúng)</div>`;
    }
  } else {
    bodyHTML = `<div class="short-input-wrap">
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
        <input type="text" class="short-input ${userAns ? 'has-val' : ''}" value="${escapeHtml(userAns || "")}" placeholder="Nhập kết quả..." oninput="inputPracShort('${q.id}', this)" />
        ${userAns && !isSub ? `<span class="opt-check-icon"><i class="fa-solid fa-check"></i></span>` : ""}
      </div>
    </div>`;
    if (isSub) {
      feedbackHTML = evalRes.isCorrect
        ? `<div class="chip chip-success" style="margin-top:12px;"><i class="fa-solid fa-check"></i> Đúng (+${evalRes.earned}đ)</div>`
        : `<div class="chip chip-danger" style="margin-top:12px;"><i class="fa-solid fa-xmark"></i> Sai — Đáp án đúng: <strong>${escapeHtml(q.answer)}</strong></div>`;
    }
  }

  const totalQ = ps.questions.length;
  return `
    <div>
      <div class="q-header">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <strong style="font-size:16.5px;">Câu ${i + 1} / ${totalQ}</strong>
        </div>
      </div>
      <div class="q-content">${q.text}</div>
      ${bodyHTML}
      ${feedbackHTML}
      ${isSub ? `<div class="solution-box"><strong>Lời giải:</strong><br/>${q.solution || "Chưa có lời giải chi tiết."}</div>` : ""}
      <div class="q-nav-footer">
        <button type="button" class="btn btn-ghost btn-sm ripple" ${i === 0 ? "disabled" : ""} onclick="stepPracticeQuestion(-1)">
          <i class="fa-solid fa-arrow-left"></i> Câu trước
        </button>
        <span class="muted">Câu ${i + 1} / ${totalQ}</span>
        ${i < totalQ - 1
          ? `<button type="button" class="btn btn-primary btn-sm ripple" onclick="stepPracticeQuestion(1)">Câu tiếp theo <i class="fa-solid fa-arrow-right"></i></button>`
          : (!isSub
              ? `<button type="button" class="btn btn-success btn-sm ripple" onclick="submitPracticeSession(false)"><i class="fa-solid fa-paper-plane"></i> Nộp & Chấm</button>`
              : `<span class="chip chip-success">Đã hoàn thành</span>`)}
      </div>
    </div>
  `;
}

function hasPracticeAnswer(q) {
  const a = state.pracSession.answers[q.id];
  if (q.part === 1) return a !== undefined;
  if (q.part === 2) return a && Object.keys(a).length > 0;
  return typeof a === "string" && a.trim() !== "";
}

function evaluatePracticeQuestion(q) {
  const sc = state.pracSession.set.scoring || { p1: 0.25, p2: 1.0, p3: 0.5 };
  return evaluateAnyQuestion(q, state.pracSession.answers[q.id], sc);
}

function selectPracMC(qId, oi, idx) {
  const ps = state.pracSession;
  if (ps.submitted) return;
  ps.idx = idx;
  ps.answers[qId] = oi;
  
  renderPracticeView(false);
}

function selectPracTF(qId, si, val, idx) {
  const ps = state.pracSession;
  if (ps.submitted) return;
  ps.idx = idx;
  if (!ps.answers[qId]) ps.answers[qId] = {};
  ps.answers[qId][si] = val;
  
  renderPracticeView(false);
}

function inputPracShort(qId, el) {
  const ps = state.pracSession;
  if (ps.submitted) return;
  ps.answers[qId] = sanitizeShortInput(el);
}

function submitPracticeSession(force = false) {
  const ps = state.pracSession;
  if (!ps.questions.length || ps.submitted) return;
  const answeredCount = ps.questions.filter(hasPracticeAnswer).length;
  if (!force && !confirm(`Bạn đã làm ${answeredCount}/${ps.questions.length} câu. Nộp bài để chấm điểm ngay?`)) return;

  let total = 0, maxP = 0, okCnt = 0, wrongQs = [];
  const sc = ps.set.scoring || { p1: 0.25, p2: 1.0, p3: 0.5, scaleMode: "raw" };

  const details = ps.questions.map(q => {
    const res = evaluatePracticeQuestion(q);
    ps.scores[q.id] = res.earned;
    total += res.earned;
    maxP += q.part === 1 ? (sc.p1 || 0.25) : q.part === 2 ? (sc.p2 || 1.0) : (sc.p3 || 0.5);
    if (res.isCorrect) okCnt++;
    else wrongQs.push(q);
    return {
      q,
      ua: ps.answers[q.id] !== undefined ? JSON.parse(JSON.stringify(ps.answers[q.id])) : null,
      earned: res.earned,
      isCorrect: res.isCorrect,
      spent: ps.qTimes[q.id] || 0
    };
  });

  const finalScore = sc.scaleMode === "scale10" && maxP > 0 ? Number(((total / maxP) * 10).toFixed(2)) : Number(total.toFixed(2));
  ps.submitted = true;
  clearInterval(ps.timerId);
  

  const banner = document.getElementById("prac-result-banner");
  banner.style.display = "flex";
  banner.innerHTML = `
    <div>
      <strong style="font-size:16px;color:var(--primary);">Điểm: ${finalScore}</strong>
      <div class="muted">Đúng tuyệt đối ${okCnt}/${ps.questions.length} câu • Sai/Chưa hoàn chỉnh: ${wrongQs.length} câu</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      ${wrongQs.length ? `<button type="button" class="btn btn-warning btn-sm ripple" onclick="startRetryWrongFromPractice()"><i class="fa-solid fa-wrench"></i> Sửa lỗi ${wrongQs.length} câu sai</button>` : `<span class="chip chip-success">Làm đúng hết!</span>`}
    </div>
  `;

  document.getElementById("prac-submit-btn").style.display = "none";
  document.getElementById("prac-retry-wrong-btn").style.display = wrongQs.length ? "inline-flex" : "none";

  // Lưu lịch sử luyện đề ngay lập tức
  const uid = state.user ? state.user.uid : "guest-local";
  const studentName = state.user ? state.user.name : "Học sinh";
  const sub = {
    id: "sub-" + Date.now(), uid, studentName,
    examId: ps.set.id, examTitle: ps.isRetryWrong ? `[Sửa sai] ${ps.set.title}` : ps.set.title,
    mode: "practice", score: finalScore, wrongCount: wrongQs.length,
    status: "Luyện đề", details, submittedAt: Date.now()
  };
  state.submissions.unshift(sub);
  saveAndBroadcast("practice_submit");
  if (isFirebaseLive && state.user) {
    fbDb.collection("submissions").doc(sub.id).set(sub).catch(() => {});
  }
  refreshAllViews();

  // Cập nhật chấm điểm & hiển thị đúng/sai ngay lập tức trên màn hình hiện tại
  renderPracticeView(false);
  renderHandwrittenSolutionView(ps.set.id);
}

function startRetryWrongFromPractice() {
  const ps = state.pracSession;
  const wrongQs = ps.questions.filter(q => !evaluatePracticeQuestion(q).isCorrect);
  if (!wrongQs.length) return showToast("Không có câu sai nào!", "info");
  startPractice(ps.set.id, JSON.parse(JSON.stringify(wrongQs)), true);
  showToast(`Đang luyện sửa lỗi ${wrongQs.length} câu sai!`, "info");
}

function switchPracticeIndex(newIdx) {
  const ps = state.pracSession;
  if (newIdx < 0 || newIdx >= ps.questions.length || newIdx === ps.idx) return;
  const curQ = ps.questions[ps.idx];
  if (wbState.ready && curQ) {
    wbSaveCurrentPageSnapshot();
    ps.boardSnapshots[curQ.id] = JSON.parse(JSON.stringify(wbState.pages));
  }
  ps.idx = newIdx;
  if (wbState.ready) {
    clearLaserLayer();
    const nextQ = ps.questions[ps.idx];
    if (nextQ && ps.boardSnapshots[nextQ.id] && ps.boardSnapshots[nextQ.id].length) {
      wbState.pages = JSON.parse(JSON.stringify(ps.boardSnapshots[nextQ.id]));
      wbState.pageIdx = 0;
      wbLoadPage(0);
    } else {
      wbInitPagesForCurrentSet();
    }
  }
  renderPracticeView(true);
}

function jumpPractice(i) { switchPracticeIndex(i); }
function stepPracticeQuestion(d) { switchPracticeIndex(state.pracSession.idx + d); }

function closePracticeSession() {
  clearInterval(state.pracSession.timerId);
  state.pracSession.active = false;
  document.getElementById("practice-overlay").style.display = "none";
  document.getElementById("teacher-board-wrap")?.classList.remove("wb-fullscreen");
}


// ---------------- PHÒNG KHẢO THÍ NGHIÊM NGẶT (CHẶN ESC / CHUYỂN TAB / CHUYỂN DESKTOP, TRUẤT QUYỀN NGAY LẬP TỨC, XEM LẠI CHI TIẾT) ----------------
async function startExam(setId) {
  if (!state.user) {
    showToast("Vui lòng đăng nhập!", "warn");
    document.getElementById("auth-modal").style.display = "grid";
    return;
  }
  const set = state.sets.find(s => s.id === setId);
  if (!set) return;
  const acc = canAccessSet(set);
  if (!acc.allowed) { notifyLockedSet(setId); return; }

  const qs = JSON.parse(JSON.stringify(set.questions));
  if (!qs.length && !(set.essayHTML && set.essayHTML.trim())) {
    return showToast("Đề thi chưa có câu hỏi!", "warn");
  }
  const qTimes = {};
  qs.forEach(q => { qTimes[q.id] = 0; });

  state.examSession = {
    active: true, set, questions: qs, answers: {}, flags: {},
    activeIdx: 0, qTimes, timeLeft: (Number(set.duration) || 60) * 60,
    timerId: null, violations: [], submitting: false, disqualified: false
  };

  const partRec = {
    id: `${set.id}_${state.user.uid}`, uid: state.user.uid, studentName: state.user.name,
    examId: set.id, examTitle: set.title, status: "Đang làm bài",
    score: "-", violations: 0, updatedAt: Date.now()
  };
  state.participants = [partRec, ...state.participants.filter(p => p.id !== partRec.id)];
  saveAndBroadcast("participant");
  if (isFirebaseLive) fbDb.collection("participants").doc(partRec.id).set(partRec).catch(() => {});

  document.getElementById("practice-overlay").style.display = "none";
  const wbWrap = document.getElementById("teacher-board-wrap"); if (wbWrap) wbWrap.style.display = "none";
  const modal = document.getElementById("exam-modal");
  modal.style.display = "flex";
  document.getElementById("exam-room-badge").textContent = set.code;
  document.getElementById("exam-active-title").textContent = set.title;
  document.getElementById("exam-viol-count").textContent = "0";
  document.getElementById("exam-viol-max").textContent = set.maxViolations || 3;
  document.getElementById("anticheat-lock").style.display = "none";

  if (modal.requestFullscreen) { try { await modal.requestFullscreen(); } catch (_) {} }
  if (navigator.keyboard && navigator.keyboard.lock) {
    try { await navigator.keyboard.lock(["Escape", "F11", "Tab"]); } catch (_) {}
  }

  renderExamSinglePage(true);
  renderExamPalette();
  startExamTimer();
  attachAntiCheatListeners();
}

function renderExamSinglePage(animatePage = false) {
  const pane = document.getElementById("exam-questions-pane");
  const ses = state.examSession;
  const qs = ses.questions;
  const idx = ses.activeIdx;
  const titles = { 1: "PHẦN I. Trắc nghiệm nhiều phương án", 2: "PHẦN II. Đúng / Sai", 3: "PHẦN III. Trả lời ngắn" };

  let qCardHtml = "";
  if (qs.length) {
    const q = qs[idx];
    const saved = ses.answers[q.id];
    const flagged = !!ses.flags[q.id];
    let inputHTML = "";

    if (q.part === 1) {
      inputHTML = `<div class="options-grid">
        ${q.options.map((opt, oi) => {
          const isSel = saved === oi;
          return `<button type="button" class="opt-btn ${isSel ? 'selected' : ''}" onclick="setExamAnswer('${q.id}', ${oi}, ${idx})">
            <span class="opt-key">${"ABCD"[oi]}</span>
            <span style="flex:1;">${opt}</span>
            ${isSel ? `<span class="opt-check-icon"><i class="fa-solid fa-check"></i></span>` : ""}
          </button>`;
        }).join("")}
      </div>`;
    } else if (q.part === 2) {
      const map = saved || {};
      inputHTML = q.statements.map((st, si) => {
        const picked = map[si];
        return `<div class="tf-row ${picked !== undefined ? 'tf-picked' : ''}">
          <div style="flex:1;"><strong>${st.label})</strong> ${st.text}</div>
          <div class="tf-actions">
            <button type="button" class="tf-btn ${picked === true ? 'active-t' : ''}" onclick="setExamTFAnswer('${q.id}', ${si}, true, ${idx})">Đúng</button>
            <button type="button" class="tf-btn ${picked === false ? 'active-f' : ''}" onclick="setExamTFAnswer('${q.id}', ${si}, false, ${idx})">Sai</button>
          </div>
        </div>`;
      }).join("");
    } else {
      inputHTML = `<div class="short-input-wrap">
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <input type="text" class="short-input ${saved ? 'has-val' : ''}" value="${escapeHtml(saved || "")}" placeholder="Nhập kết quả..." oninput="setExamShortAnswer('${q.id}', this, ${idx})" />
          ${saved ? `<span class="opt-check-icon"><i class="fa-solid fa-check"></i></span>` : ""}
        </div>
      </div>`;
    }

    const curQEl = document.getElementById("exam-cur-q-timer");
    if (curQEl) curQEl.textContent = fmtMMSS(ses.qTimes[q.id] || 0);

    qCardHtml = `
      <div class="exam-q-card ${animatePage ? 'q-stage-anim' : ''}">
        <div class="part-banner">${titles[q.part] || "PHẦN THI"}</div>
        <div class="q-header">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <strong style="font-size:16.5px;">Câu ${idx + 1} / ${qs.length}</strong>
          </div>
          <button type="button" class="btn btn-sm ${flagged ? 'btn-warning' : 'btn-ghost'}" onclick="toggleExamFlag('${q.id}')">
            <i class="fa-solid fa-flag"></i> ${flagged ? "Đã đánh dấu" : "Xem lại"}
          </button>
        </div>
        <div class="q-content">${q.text}</div>
        ${inputHTML}
        <div class="q-nav-footer">
          <button type="button" class="btn btn-ghost btn-sm ripple" ${idx === 0 ? "disabled" : ""} onclick="stepExamQuestion(-1)">
            <i class="fa-solid fa-arrow-left"></i> Câu trước
          </button>
          <span class="muted">Câu ${idx + 1} / ${qs.length}</span>
          ${idx < qs.length - 1
            ? `<button type="button" class="btn btn-primary btn-sm ripple" onclick="stepExamQuestion(1)">Câu tiếp theo <i class="fa-solid fa-arrow-right"></i></button>`
            : `<button type="button" class="btn btn-danger btn-sm ripple" onclick="confirmSubmitExam(false)"><i class="fa-solid fa-paper-plane"></i> Nộp bài</button>`}
        </div>
      </div>`;
  }

  let essayBlock = "";
  if (ses.set.essayHTML && ses.set.essayHTML.trim()) {
    essayBlock = `
      <div class="essay-box">
        <div class="part-banner"><i class="fa-solid fa-pen-fancy"></i> PHẦN TỰ LUẬN</div>
        <div class="q-content">${ses.set.essayHTML}</div>
        <div class="zalo-note"><i class="fa-solid fa-comment-dots"></i> Làm bài tự luận ra giấy và chụp ảnh gửi riêng qua Zalo cho giáo viên.</div>
      </div>`;
  }

  pane.innerHTML = qCardHtml + essayBlock;
  renderMath(pane);
}

function setExamAnswer(qId, val, idx) {
  const ses = state.examSession;
  ses.activeIdx = idx;
  ses.answers[qId] = val;
  
  renderExamSinglePage(false);
  renderExamPalette();
}

function setExamTFAnswer(qId, si, val, idx) {
  const ses = state.examSession;
  ses.activeIdx = idx;
  if (!ses.answers[qId]) ses.answers[qId] = {};
  ses.answers[qId][si] = val;
  
  renderExamSinglePage(false);
  renderExamPalette();
}

function setExamShortAnswer(qId, el, idx) {
  const ses = state.examSession;
  ses.activeIdx = idx;
  ses.answers[qId] = sanitizeShortInput(el);
  renderExamPalette();
}

function toggleExamFlag(qId) {
  state.examSession.flags[qId] = !state.examSession.flags[qId];
  renderExamSinglePage(false);
  renderExamPalette();
}

function isQDone(q) {
  const a = state.examSession.answers[q.id];
  if (q.part === 1) return a !== undefined;
  if (q.part === 2) return a && Object.keys(a).length === q.statements.length;
  return typeof a === "string" && a.trim() !== "";
}

function renderExamPalette() {
  const qs = state.examSession.questions;
  const done = qs.filter(isQDone).length;
  document.getElementById("exam-progress-text").textContent = `${done}/${qs.length}`;
  document.getElementById("exam-progress-fill").style.width = `${qs.length ? (done / qs.length) * 100 : 0}%`;
  document.getElementById("exam-palette-grid").innerHTML = qs.map((q, i) => {
    const cls = [state.examSession.flags[q.id] ? "flag" : isQDone(q) ? "done" : "", i === state.examSession.activeIdx ? "active" : ""].join(" ");
    return `<button type="button" class="pal-btn ${cls}" onclick="focusExamQuestion(${i})">${i + 1}</button>`;
  }).join("");
}

function focusExamQuestion(i) {
  const ses = state.examSession;
  if (i < 0 || i >= ses.questions.length) return;
  ses.activeIdx = i;
  renderExamSinglePage(true);
  renderExamPalette();
}

function stepExamQuestion(d) {
  focusExamQuestion(state.examSession.activeIdx + d);
}

function startExamTimer() {
  clearInterval(state.examSession.timerId);
  state.examSession.timerId = setInterval(() => {
    const ses = state.examSession;
    if (!ses.active) return;

    // Giám sát liên tục trạng thái mất tiêu điểm / thoát toàn màn hình mỗi giây
    if (!ses.submitting && !ses.disqualified) {
      if (!document.hasFocus()) {
        recordExamViolation("Cửa sổ phòng thi bị mất tiêu điểm / chuyển ứng dụng hoặc chuyển Desktop.");
      } else if (!document.fullscreenElement) {
        recordExamViolation("Thoát khỏi chế độ toàn màn hình phòng thi (ESC).");
      }
    }

    const activeQ = ses.questions[ses.activeIdx];
    if (activeQ) {
      ses.qTimes[activeQ.id] = (ses.qTimes[activeQ.id] || 0) + 1;
      const formatted = fmtMMSS(ses.qTimes[activeQ.id]);

      const topTag = document.getElementById("exam-cur-q-timer");
      if (topTag) topTag.textContent = formatted;
    }
    document.getElementById("exam-time-text").textContent = fmtMMSS(ses.timeLeft);
    document.getElementById("exam-timer").classList.toggle("urgent", ses.timeLeft <= 300);
    if (ses.timeLeft <= 0) { clearInterval(ses.timerId); confirmSubmitExam(true, "Hết giờ"); return; }
    ses.timeLeft--;
  }, 1000);
}

function adjustExamFont(d) {
  const cur = parseInt(getComputedStyle(document.documentElement).getPropertyValue("--exam-font-size")) || 15.5;
  document.documentElement.style.setProperty("--exam-font-size", `${Math.min(22, Math.max(13, cur + d))}px`);
}

let lastViol = 0;
function onFsChange() {
  if (state.examSession.active && !state.examSession.submitting && !document.fullscreenElement) {
    recordExamViolation("Nhấn ESC hoặc thoát chế độ Toàn màn hình.");
  }
}
function onVisChange() {
  if (state.examSession.active && !state.examSession.submitting && document.hidden) {
    recordExamViolation("Chuyển sang tab khác hoặc thu nhỏ trình duyệt.");
  }
}
function onWinBlur() {
  if (state.examSession.active && !state.examSession.submitting) {
    recordExamViolation("Chuyển sang cửa sổ khác hoặc chuyển Desktop ảo.");
  }
}
function onBeforeUnloadExam(e) {
  if (state.examSession.active && !state.examSession.submitting) {
    e.preventDefault();
    e.returnValue = "";
  }
}
function attachAntiCheatListeners() {
  document.addEventListener("fullscreenchange", onFsChange);
  document.addEventListener("visibilitychange", onVisChange);
  window.addEventListener("blur", onWinBlur);
  window.addEventListener("beforeunload", onBeforeUnloadExam);
}
function detachAntiCheatListeners() {
  document.removeEventListener("fullscreenchange", onFsChange);
  document.removeEventListener("visibilitychange", onVisChange);
  window.removeEventListener("blur", onWinBlur);
  window.removeEventListener("beforeunload", onBeforeUnloadExam);
  if (navigator.keyboard && navigator.keyboard.unlock) {
    try { navigator.keyboard.unlock(); } catch (_) {}
  }
}

function recordExamViolation(reason) {
  const ses = state.examSession;
  if (!ses.active || ses.submitting || ses.disqualified) return;
  if (Date.now() - lastViol < 1200) return;
  lastViol = Date.now();

  ses.violations.push({ time: new Date().toLocaleTimeString("vi-VN"), reason });
  
  const c = ses.violations.length, max = Number(ses.set.maxViolations) || 3;

  const pIdx = state.participants.findIndex(p => p.id === `${ses.set.id}_${state.user.uid}`);
  if (pIdx !== -1) {
    state.participants[pIdx].violations = c;
    state.participants[pIdx].status = c >= max ? "Bị truất quyền thi" : `Cảnh báo (${c}/${max})`;
    saveAndBroadcast("participant");
  }

  document.getElementById("exam-viol-count").textContent = c;
  document.getElementById("lock-viol-display").textContent = `${c}/${max}`;

  if (c >= max) {
    disqualifyExamSession(reason, c, max);
    return;
  }

  document.getElementById("anticheat-title").textContent = "CẢNH BÁO VI PHẠM QUY CHẾ!";
  document.getElementById("anticheat-reason").textContent = reason;
  const actBtn = document.getElementById("anticheat-action-btn");
  actBtn.className = "btn btn-primary ripple";
  actBtn.innerHTML = `<i class="fa-solid fa-expand"></i> Quay lại phòng thi ngay`;
  actBtn.onclick = resumeExamFullscreen;
  document.getElementById("anticheat-lock").style.display = "grid";
}

function disqualifyExamSession(reason, c, max) {
  const ses = state.examSession;
  ses.disqualified = true;
  ses.active = false;
  clearInterval(ses.timerId);
  detachAntiCheatListeners();

  // Hủy toàn bộ bài làm hiện tại -> Bắt buộc thí sinh phải vào thi lại từ đầu
  ses.answers = {};
  const partRec = {
    id: `${ses.set.id}_${state.user.uid}`, uid: state.user.uid, studentName: state.user.name,
    examId: ses.set.id, examTitle: ses.set.title, status: "Bị truất quyền thi",
    score: 0, violations: c, updatedAt: Date.now()
  };
  state.participants = [partRec, ...state.participants.filter(p => p.id !== partRec.id)];
  saveAndBroadcast("disqualified");
  if (isFirebaseLive) {
    fbDb.collection("participants").doc(partRec.id).set(partRec).catch(() => {});
  }

  document.getElementById("anticheat-title").textContent = "TRUẤT QUYỀN THI NGAY LẬP TỨC!";
  document.getElementById("anticheat-reason").innerHTML =
    `Bạn đã vi phạm quy chế <strong>${c}/${max}</strong> lần (${escapeHtml(reason)}).<br/>Toàn bộ bài làm hiện tại đã bị hủy bỏ. Bạn bắt buộc phải thi lại từ đầu!`;
  const actBtn = document.getElementById("anticheat-action-btn");
  actBtn.className = "btn btn-danger ripple";
  actBtn.innerHTML = `<i class="fa-solid fa-rotate-right"></i> Rời phòng & Thi lại từ đầu`;
  actBtn.onclick = exitDisqualifiedExam;
  document.getElementById("anticheat-lock").style.display = "grid";
  refreshAllViews();
}

async function exitDisqualifiedExam() {
  if (document.fullscreenElement) { try { await document.exitFullscreen(); } catch (_) {} }
  document.getElementById("anticheat-lock").style.display = "none";
  document.getElementById("exam-modal").style.display = "none";
  const actBtn = document.getElementById("anticheat-action-btn");
  actBtn.className = "btn btn-primary ripple";
  showToast("Đã truất quyền thi do vi phạm quy chế. Bạn phải thi lại từ đầu!", "error");
}

async function resumeExamFullscreen() {
  const m = document.getElementById("exam-modal");
  if (m.requestFullscreen && !document.fullscreenElement) { try { await m.requestFullscreen(); } catch (_) {} }
  document.getElementById("anticheat-lock").style.display = "none";
}

async function confirmSubmitExam(force = false, statusNote = "Hoàn thành") {
  const ses = state.examSession;
  if (ses.disqualified) return;
  if (!force && !confirm("Bạn chắc chắn muốn nộp bài thi khảo thí?")) return;

  ses.submitting = true; ses.active = false;
  clearInterval(ses.timerId); detachAntiCheatListeners();

  const sc = ses.set.scoring || { p1: 0.25, p2: 1.0, p3: 0.5, scaleMode: "raw" };
  let total = 0, maxP = 0;
  const details = ses.questions.map(q => {
    const ua = ses.answers[q.id];
    const res = evaluateAnyQuestion(q, ua, sc);
    maxP += q.part === 1 ? (sc.p1 || 0.25) : q.part === 2 ? (sc.p2 || 1.0) : (sc.p3 || 0.5);
    total += res.earned;
    return {
      q,
      ua: ua !== undefined ? JSON.parse(JSON.stringify(ua)) : null,
      earned: res.earned,
      isCorrect: res.isCorrect,
      spent: ses.qTimes[q.id] || 0
    };
  });

  const finalScore = sc.scaleMode === "scale10" && maxP > 0 ? Number(((total / maxP) * 10).toFixed(2)) : Number(total.toFixed(2));

  if (document.fullscreenElement) { try { await document.exitFullscreen(); } catch (_) {} }
  document.getElementById("exam-modal").style.display = "none";

  const sub = {
    id: "sub-" + Date.now(), uid: state.user.uid, studentName: state.user.name,
    examId: ses.set.id, examTitle: ses.set.title, mode: "exam",
    score: finalScore, violations: ses.violations, status: statusNote,
    details, submittedAt: Date.now()
  };
  state.submissions.unshift(sub);

  const partRec = {
    id: `${ses.set.id}_${state.user.uid}`, subId: sub.id, uid: state.user.uid, studentName: state.user.name,
    examId: ses.set.id, examTitle: ses.set.title, status: statusNote,
    score: finalScore, violations: ses.violations.length, updatedAt: Date.now()
  };
  state.participants = [partRec, ...state.participants.filter(p => p.id !== partRec.id)];
  saveAndBroadcast("submit");
  if (isFirebaseLive) {
    fbDb.collection("submissions").doc(sub.id).set(sub).catch(() => {});
    fbDb.collection("participants").doc(partRec.id).set(partRec).catch(() => {});
  }

  
  // Hiển thị ngay kết quả kèm toàn bộ chi tiết từng câu đúng/sai và lời giải như Luyện đề
  showSubmissionResultModal(sub);
  refreshAllViews();
}

function formatUserAnswerSummary(d) {
  const q = d.q, ua = d.ua;
  if (q.part === 1) {
    const uStr = ua !== null && ua !== undefined ? `<strong>${"ABCD"[ua]}</strong>` : `<span class="muted">Bỏ trống</span>`;
    const cStr = `<strong>${"ABCD"[q.answer]}</strong>`;
    return `Bạn chọn: ${uStr} &nbsp;•&nbsp; Đáp án đúng: <span style="color:var(--success)">${cStr}</span>`;
  }
  if (q.part === 2) {
    const map = ua || {};
    const uArr = q.statements.map((st, idx) => `${st.label}:${map[idx] === true ? "Đ" : map[idx] === false ? "S" : "-"}`).join(" ");
    const cArr = q.statements.map(st => `${st.label}:${st.answer ? "Đ" : "S"}`).join(" ");
    return `Bạn chọn: <strong>${uArr}</strong> &nbsp;•&nbsp; Đáp án đúng: <span style="color:var(--success)"><strong>${cArr}</strong></span>`;
  }
  const uStr = ua ? `<strong>${escapeHtml(ua)}</strong>` : `<span class="muted">Bỏ trống</span>`;
  return `Bạn nhập: ${uStr} &nbsp;•&nbsp; Đáp án đúng: <span style="color:var(--success)"><strong>${escapeHtml(q.answer)}</strong></span>`;
}

function showSubmissionResultModal(sub) {
  document.getElementById("result-modal-title").innerHTML = `<i class="fa-solid fa-award"></i> Chi tiết kết quả & Đáp án từng câu`;
  const body = document.getElementById("result-modal-body");
  const details = sub.details || [];
  const rightCount = details.filter(d => d.isCorrect).length;

  let html = `
    <div class="stat-box" style="margin-bottom:14px;justify-content:space-between;flex-wrap:wrap;">
      <div>
        <div class="muted">${escapeHtml(sub.examTitle)} • ${new Date(sub.submittedAt).toLocaleString("vi-VN")}</div>
        <h2 style="font-size:28px;color:var(--primary);">${sub.score} điểm</h2>
        ${details.length ? `<div class="muted">Đúng ${rightCount}/${details.length} câu • Sai ${details.length - rightCount} câu</div>` : ""}
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <span class="chip chip-primary">${escapeHtml(sub.status)}</span>
      </div>
    </div>`;

  if (details.length) {
    html += details.map((d, i) => {
      const q = d.q;
      let optionsBreakdown = "";
      if (q.part === 1) {
        optionsBreakdown = `<div class="options-grid" style="margin-bottom:10px;">
          ${q.options.map((opt, oi) => {
            const isCorrectOpt = oi === q.answer;
            const isUserOpt = d.ua === oi;
            let cls = isCorrectOpt ? "correct" : (isUserOpt ? "wrong" : "");
            let badge = isCorrectOpt ? `<span class="opt-tag ok"><i class="fa-solid fa-check"></i> Đúng</span>` : (isUserOpt ? `<span class="opt-tag bad"><i class="fa-solid fa-xmark"></i> Bạn chọn</span>` : "");
            return `<div class="opt-btn ${cls}" style="cursor:default;pointer-events:none;">
              <span class="opt-key">${"ABCD"[oi]}</span>
              <span style="flex:1;">${opt}</span>
              ${badge}
            </div>`;
          }).join("")}
        </div>`;
      }
      return `
      <div class="exam-q-card" style="margin-bottom:12px;border-color:${d.isCorrect ? 'var(--success)' : 'var(--danger)'};">
        <div class="q-header">
          <div style="display:flex;align-items:center;gap:8px;">
            <strong>Câu ${i + 1}</strong>
            <span class="q-timer-tag">${fmtMMSS(d.spent)}</span>
          </div>
          <span class="chip ${d.isCorrect ? 'chip-success' : 'chip-danger'}">${d.isCorrect ? "Đúng" : "Sai"} (+${d.earned}đ)</span>
        </div>
        <div class="q-content">${q.text}</div>
        ${optionsBreakdown}
        <div style="font-size:13px;padding:8px 11px;border-radius:9px;background:var(--bg-base);margin-bottom:8px;">
          ${formatUserAnswerSummary(d)}
        </div>
        ${q.solution ? `<div class="solution-box"><strong>Lời giải:</strong> ${q.solution}</div>` : ""}
      </div>`;
    }).join("");
  }

  body.innerHTML = html;
  document.getElementById("result-modal").style.display = "grid";
  renderMath(body);
}

// ---------------- KHUNG FORM SOẠN TRỰC TIẾP DÀNH CHO GIÁO VIÊN + ĐỌC FILE WORD (.DOCX) ----------------
function addManualQuestionCard(part = 1) {
  const newQ = {
    id: "mq-" + Date.now() + "-" + Math.floor(Math.random() * 1000),
    part,
    text: "",
    options: part === 1 ? ["", "", "", ""] : [],
    statements: part === 2 ? [
      { label: "a", text: "", answer: true },
      { label: "b", text: "", answer: false },
      { label: "c", text: "", answer: true },
      { label: "d", text: "", answer: false }
    ] : [],
    answer: part === 1 ? 0 : "",
    solution: ""
  };
  state.parsedWordQuestions.push(newQ);
  document.getElementById("word-preview-area").style.display = "block";
  document.getElementById("word-preview-summary").textContent = `Danh sách câu hỏi (${state.parsedWordQuestions.length} câu)`;
  renderParsedWordEditor();
  showToast(`Đã thêm câu hỏi Phần ${part} vào khung soạn.`, "info");
}

function insertSymbolAtCursor(sym) {
  const el = state.lastFocusedEditor;
  if (!el) return showToast("Hãy đặt con trỏ chuột vào ô nhập câu hỏi hoặc phương án trước.", "warn");
  el.focus();
  if (el.tagName === "INPUT" || el.tagName === "TEXTAREA") {
    const start = el.selectionStart || 0, end = el.selectionEnd || 0;
    el.value = el.value.slice(0, start) + sym + el.value.slice(end);
    el.dispatchEvent(new Event("input"));
  } else {
    document.execCommand("insertText", false, sym);
    el.dispatchEvent(new Event("input"));
  }
}

function handleRichEditorPaste(e) {
  const items = e.clipboardData?.items || [];
  for (const it of items) {
    if (it.type.startsWith("image/")) {
      e.preventDefault();
      const file = it.getAsFile();
      if (file) {
        compressImageFile(file, 900, 0.85).then(dataUrl => {
          document.execCommand("insertHTML", false, `<img src="${dataUrl}" alt="Hình công thức"/>`);
          e.target.dispatchEvent(new Event("input"));
        });
      }
      return;
    }
  }
}

function renderParsedWordEditor() {
  const box = document.getElementById("word-preview-list");
  document.getElementById("word-preview-summary").textContent = `Danh sách câu hỏi (${state.parsedWordQuestions.length} câu)`;

  box.innerHTML = state.parsedWordQuestions.map((q, i) => {
    let ansCtrl = "";
    let bodyEditor = "";

    if (q.part === 1) {
      ansCtrl = `<select class="input-sm" onchange="state.parsedWordQuestions[${i}].answer=Number(this.value)">
        ${["A", "B", "C", "D"].map((ch, oi) => `<option value="${oi}" ${q.answer === oi ? "selected" : ""}>Đáp án đúng: ${ch}</option>`).join("")}
      </select>`;
      bodyEditor = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;">
        ${[0, 1, 2, 3].map(oi => `
          <div style="display:flex;align-items:center;gap:6px;">
            <span class="opt-key" style="width:26px;height:26px;font-size:12px;">${"ABCD"[oi]}</span>
            <div class="rich-opt-editor" contenteditable="true" data-placeholder="Phương án ${"ABCD"[oi]}..."
              onfocus="state.lastFocusedEditor=this"
              onpaste="handleRichEditorPaste(event)"
              oninput="state.parsedWordQuestions[${i}].options[${oi}]=this.innerHTML">${q.options[oi] || ""}</div>
          </div>
        `).join("")}
      </div>`;
    } else if (q.part === 2) {
      ansCtrl = `<div style="display:flex;gap:5px;flex-wrap:wrap;">${q.statements.map((st, si) => `
        <button type="button" class="btn btn-xs ${st.answer ? 'btn-success' : 'btn-danger'}" onclick="toggleParsedTF(${i}, ${si})">${st.label}: ${st.answer ? "Đúng" : "Sai"}</button>
      `).join("")}</div>`;
      bodyEditor = `<div style="display:flex;flex-direction:column;gap:6px;margin-top:8px;">
        ${q.statements.map((st, si) => `
          <div style="display:flex;align-items:center;gap:6px;">
            <strong>${st.label})</strong>
            <div class="rich-opt-editor" contenteditable="true" data-placeholder="Nội dung mệnh đề ${st.label})..."
              onfocus="state.lastFocusedEditor=this"
              onpaste="handleRichEditorPaste(event)"
              oninput="state.parsedWordQuestions[${i}].statements[${si}].text=this.innerHTML">${st.text || ""}</div>
          </div>
        `).join("")}
      </div>`;
    } else {
      ansCtrl = `<input type="text" class="input-sm" style="width:140px;" value="${escapeHtml(q.answer)}" placeholder="Đáp án số..."
        onfocus="state.lastFocusedEditor=this"
        oninput="state.parsedWordQuestions[${i}].answer=this.value" />`;
    }

    return `
      <div class="preview-q-item">
        <div class="q-header" style="margin-bottom:8px;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <strong>Câu ${i + 1}</strong>
            <span class="chip ${q.part === 1 ? 'chip-success' : q.part === 2 ? 'chip-warn' : 'chip-primary'}">Phần ${q.part}</span>
            ${ansCtrl}
          </div>
          <button type="button" class="btn btn-danger btn-xs" onclick="removeParsedQ(${i})" title="Xóa câu"><i class="fa-solid fa-trash"></i></button>
        </div>
        <div class="rich-q-editor" contenteditable="true" data-placeholder="Nhập hoặc dán đề bài câu ${i + 1} từ Word / MathType / Ảnh..."
          onfocus="state.lastFocusedEditor=this"
          onpaste="handleRichEditorPaste(event)"
          oninput="state.parsedWordQuestions[${i}].text=this.innerHTML">${q.text || ""}</div>
        ${bodyEditor}
        <div style="margin-top:8px;">
          <div class="rich-opt-editor" contenteditable="true" data-placeholder="Lời giải chi tiết (tùy chọn)..."
            onfocus="state.lastFocusedEditor=this"
            onpaste="handleRichEditorPaste(event)"
            oninput="state.parsedWordQuestions[${i}].solution=this.innerHTML">${q.solution || ""}</div>
        </div>
      </div>`;
  }).join("");
  renderMath(box);
}

const OriginWordEngine = (() => {
  const W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
  const M_NS = "http://schemas.openxmlformats.org/officeDocument/2006/math";
  const R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

  function classifyFillHex(hex) {
    if (!hex || hex === "auto" || hex.length !== 6) return "none";
    const r = parseInt(hex.slice(0, 2), 16), g = parseInt(hex.slice(2, 4), 16), b = parseInt(hex.slice(4, 6), 16);
    if (r > 246 && g > 246 && b > 246) return "none";
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    if (max - min < 14) return "none";
    let h = 0;
    if (max === r) h = ((g - b) / (max - min)) * 60;
    else if (max === g) h = (2 + (b - r) / (max - min)) * 60;
    else h = (4 + (r - g) / (max - min)) * 60;
    if (h < 0) h += 360;
    if (h >= 75 && h <= 165) return "green";
    if (h >= 5 && h <= 58) return "orange";
    if (h >= 180 && h <= 260) return "blue";
    return "other";
  }

  function ommlToLatex(node) {
    if (!node) return "";
    const tag = node.localName;
    const children = () => Array.from(node.childNodes).map(ommlToLatex).join("");
    const findChild = (name) => Array.from(node.children || []).find(c => c.localName === name);

    if (tag === "t") return node.textContent || "";
    if (tag === "r") {
      const txt = Array.from(node.children || []).filter(c => c.localName === "t").map(c => c.textContent).join("");
      return txt
        .replace(/≤/g, "\\le ").replace(/≥/g, "\\ge ").replace(/≠/g, "\\ne ")
        .replace(/∞/g, "\\infty ").replace(/π/g, "\\pi ").replace(/α/g, "\\alpha ")
        .replace(/β/g, "\\beta ").replace(/γ/g, "\\gamma ").replace(/Δ/g, "\\Delta ")
        .replace(/±/g, "\\pm ").replace(/×/g, "\\times ").replace(/·/g, "\\cdot ")
        .replace(/∈/g, "\\in ").replace(/∉/g, "\\notin ").replace(/⊂/g, "\\subset ")
        .replace(/∪/g, "\\cup ").replace(/∩/g, "\\cap ").replace(/∀/g, "\\forall ")
        .replace(/∃/g, "\\exists ").replace(/⇒/g, "\\Rightarrow ").replace(/⇔/g, "\\Leftrightarrow ")
        .replace(/→/g, "\\to ").replace(/⊥/g, "\\perp ").replace(/°/g, "^\\circ ");
    }
    if (tag === "f") return `\\frac{${ommlToLatex(findChild("num")) }}{${ommlToLatex(findChild("den")) }}`;
    if (tag === "rad") {
      const deg = ommlToLatex(findChild("deg")).trim();
      const e = ommlToLatex(findChild("e"));
      return deg ? `\\sqrt[${deg}]{${e}}` : `\\sqrt{${e}}`;
    }
    if (tag === "sSup") return `{${ommlToLatex(findChild("e"))}}^{${ommlToLatex(findChild("sup"))}}`;
    if (tag === "sSub") return `{${ommlToLatex(findChild("e"))}}_{${ommlToLatex(findChild("sub"))}}`;
    if (tag === "sSubSup") return `{${ommlToLatex(findChild("e"))}}_{${ommlToLatex(findChild("sub"))}}^{${ommlToLatex(findChild("sup"))}}`;
    if (tag === "nary") {
      const chrEl = node.getElementsByTagNameNS(M_NS, "chr")[0];
      const ch = chrEl?.getAttribute("m:val") || chrEl?.getAttribute("val") || "∫";
      const op = ch === "∑" ? "\\sum" : ch === "∏" ? "\\prod" : "\\int";
      const sub = ommlToLatex(findChild("sub")).trim();
      const sup = ommlToLatex(findChild("sup")).trim();
      return `${op}${sub ? `_{${sub}}` : ""}${sup ? `^{${sup}}` : ""} ${ommlToLatex(findChild("e"))}`;
    }
    if (tag === "d") {
      const beg = node.getElementsByTagNameNS(M_NS, "begChr")[0]?.getAttribute("m:val") || "(";
      const end = node.getElementsByTagNameNS(M_NS, "endChr")[0]?.getAttribute("m:val") || ")";
      const inner = Array.from(node.children || []).filter(c => c.localName === "e").map(ommlToLatex).join(",");
      return `\\left${beg === "{" ? "\\{" : beg}${inner}\\right${end === "}" ? "\\}" : end}`;
    }
    if (tag === "acc") {
      const chr = node.getElementsByTagNameNS(M_NS, "chr")[0]?.getAttribute("m:val") || "";
      const e = ommlToLatex(findChild("e"));
      if (chr.includes("→") || chr === "\u20D7") return `\\overrightarrow{${e}}`;
      if (chr === "^" || chr === "\u0302") return `\\widehat{${e}}`;
      return `\\overline{${e}}`;
    }
    return children();
  }

  function extractParagraphHtml(pEl, mediaMap) {
    let out = "";
    for (const child of Array.from(pEl.childNodes)) {
      if (child.localName === "oMath" || child.localName === "oMathPara") {
        const latex = ommlToLatex(child).trim();
        if (latex) out += `$${latex}$`;
      } else if (child.localName === "r") {
        for (const el of child.getElementsByTagName("*")) {
          if (el.localName === "blip") {
            const rId = el.getAttributeNS(R_NS, "embed") || el.getAttribute("r:embed");
            if (rId && mediaMap[rId]) out += `<img src="${mediaMap[rId]}" alt="Hình"/>`;
          }
        }
        const texts = Array.from(child.childNodes).filter(c => c.localName === "t" || c.localName === "br");
        let runText = texts.map(n => n.localName === "br" ? "<br/>" : escapeHtml(n.textContent)).join("");
        if (runText) {
          const rPr = Array.from(child.children || []).find(c => c.localName === "rPr");
          const isBold = rPr && Array.from(rPr.children).some(c => c.localName === "b" && c.getAttribute("w:val") !== "0");
          const isSub = rPr && Array.from(rPr.children).some(c => c.localName === "vertAlign" && c.getAttribute("w:val") === "subscript");
          const isSup = rPr && Array.from(rPr.children).some(c => c.localName === "vertAlign" && c.getAttribute("w:val") === "superscript");
          const colorEl = rPr && Array.from(rPr.children).find(c => c.localName === "color");
          const colVal = colorEl ? (colorEl.getAttribute("w:val") || colorEl.getAttribute("val") || "").toUpperCase() : "";
          const hasUnderline = rPr && Array.from(rPr.children).some(c => c.localName === "u" && c.getAttribute("w:val") !== "none");
          const hasHighlight = rPr && Array.from(rPr.children).some(c => c.localName === "highlight");
          const isMarkedCorrect = hasUnderline || hasHighlight || (colVal && colVal !== "AUTO" && colVal !== "000000" && colVal !== "FFFFFF" && colVal !== "111111");

          if (isSub) runText = `<sub>${runText}</sub>`;
          if (isSup) runText = `<sup>${runText}</sup>`;
          if (isBold && !runText.includes("$")) runText = `<strong>${runText}</strong>`;
          if (isMarkedCorrect) runText = `<span data-marked-ans="1">${runText}</span>`;
          out += runText;
        }
      }
    }
    return out.trim();
  }

  function extractCellHtml(tcEl, mediaMap) {
    return Array.from(tcEl.children || []).filter(c => c.localName === "p").map(p => extractParagraphHtml(p, mediaMap)).filter(Boolean).join("<br/>").trim();
  }

  function stripTags(html) {
    return String(html || "").replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();
  }

  function getRowFillColor(trEl) {
    for (const tc of Array.from(trEl.children || []).filter(c => c.localName === "tc")) {
      for (const shd of tc.getElementsByTagNameNS(W_NS, "shd")) {
        const cls = classifyFillHex(shd.getAttribute("w:fill") || shd.getAttribute("fill"));
        if (cls !== "none") return cls;
      }
    }
    return "none";
  }

  function getRowContent(trEl, mediaMap) {
    const cells = Array.from(trEl.children || []).filter(c => c.localName === "tc").map(tc => extractCellHtml(tc, mediaMap));
    return { cells, texts: cells.map(stripTags) };
  }

  function parseTfAnswerString(raw) {
    const s = raw.toUpperCase();
    const labeled = [...s.matchAll(/[A-D]\s*[:.)-]\s*(ĐÚNG|SAI|Đ|D|S|T|F|1|0)/g)];
    const tokens = [];
    if (labeled.length >= 4) {
      labeled.slice(0, 4).forEach(m => tokens.push(["ĐÚNG", "Đ", "D", "T", "1"].includes(m[1])));
      return tokens;
    }
    [...s.matchAll(/(ĐÚNG|SAI|Đ|D|S|T|F|1|0)/g)].slice(0, 4).forEach(m => tokens.push(["ĐÚNG", "Đ", "D", "T", "1"].includes(m[1])));
    while (tokens.length < 4) tokens.push(false);
    return tokens;
  }

  function splitInlineOptions(rawHtml) {
    const plain = stripTags(rawHtml);
    if (!/(?:^|\s)[A-D]\s*[.)]\s*/.test(plain)) return null;
    const parts = rawHtml.split(/(?=(?:^|>|\s)\*?\s*[A-D]\s*[.)]\s*)/g).map(s => s.trim()).filter(Boolean);
    const out = {};
    let markedIdx = -1;
    parts.forEach(seg => {
      const pSeg = stripTags(seg);
      const m = pSeg.match(/^(\*)?\s*([A-D])\s*[.)]\s*(.*)$/i);
      if (m) {
        const idx = "ABCD".indexOf(m[2].toUpperCase());
        if (m[1] || seg.includes('data-marked-ans="1"')) markedIdx = idx;
        out[idx] = seg.replace(/^(?:<[^>]+>|\s)*\*?\s*[A-D]\s*[.)]\s*/i, "").replace(/<\/?span[^>]*>/g, "").trim();
      }
    });
    return Object.keys(out).length >= 2 ? { out, markedIdx } : null;
  }

  async function parseDocx(file) {
    if (typeof JSZip === "undefined") throw new Error("Thiếu thư viện JSZip.");
    const zip = await JSZip.loadAsync(await file.arrayBuffer());
    const docXmlStr = await zip.file("word/document.xml").async("string");
    const relsFile = zip.file("word/_rels/document.xml.rels");
    const mediaMap = {};

    if (relsFile) {
      const relsXml = new DOMParser().parseFromString(await relsFile.async("string"), "application/xml");
      for (const rel of Array.from(relsXml.getElementsByTagName("Relationship"))) {
        const target = rel.getAttribute("Target") || "";
        if (target.startsWith("media/")) {
          const mediaZip = zip.file("word/" + target);
          if (mediaZip) {
            const b64 = await mediaZip.async("base64");
            const ext = target.split(".").pop().toLowerCase();
            mediaMap[rel.getAttribute("Id")] = `data:image/${ext === "png" ? "png" : ext === "gif" ? "gif" : "jpeg"};base64,${b64}`;
          }
        }
      }
    }

    const xml = new DOMParser().parseFromString(docXmlStr, "application/xml");
    const body = xml.getElementsByTagNameNS(W_NS, "body")[0];
    const bodyNodes = Array.from(body.children || []);

    let questions = [];
    let essayParts = [];
    let inEssay = false;
    let colorTableFound = false;

    for (const node of bodyNodes) {
      if (node.localName === "p") {
        const pHtml = extractParagraphHtml(node, mediaMap);
        const pTxt = stripTags(pHtml);
        if (/PHẦN\s*TỰ\s*LUẬN|II\.\s*TỰ\s*LUẬN|TỰ\s*LUẬN\s*\(/i.test(pTxt)) { inEssay = true; continue; }
        if (inEssay && pHtml) essayParts.push(`<p>${pHtml}</p>`);
      } else if (node.localName === "tbl") {
        const rows = Array.from(node.children || []).filter(c => c.localName === "tr");
        if (inEssay) {
          rows.forEach(tr => { const j = getRowContent(tr, mediaMap).cells.filter(Boolean).join(" — "); if (j) essayParts.push(`<p>${j}</p>`); });
          continue;
        }
        const rowColors = rows.map(getRowFillColor);
        if (rowColors.some(c => c === "green" || c === "orange" || c === "blue")) {
          colorTableFound = true;
          let i = 0;
          while (i < rows.length) {
            const col = rowColors[i];
            if (col === "green" || col === "orange" || col === "blue") {
              const qRow = getRowContent(rows[i], mediaMap);
              let qHtml = qRow.cells.length >= 2 && (!qRow.texts[0] || /^Câu\s*\d*/i.test(qRow.texts[0])) ? qRow.cells[1] : qRow.cells.filter(Boolean).join(" ");
              qHtml = qHtml.replace(/^(<[^>]+>)*\s*Câu\s*\d+\s*[:.]?\s*/i, "").replace(/<\/?span[^>]*>/g, "").trim();

              const subRows = [];
              let j = i + 1;
              while (j < rows.length && rowColors[j] === "none") { subRows.push(getRowContent(rows[j], mediaMap)); j++; }
              i = j;
              if (!stripTags(qHtml) && !qHtml.includes("<img")) continue;

              let ansRaw = "", solHtml = "";
              const contentRows = [];
              for (const sr of subRows) {
                const t0 = (sr.texts[0] || "").trim();
                const fullT = sr.texts.join(" ").trim();
                if (/^Đáp\s*án/i.test(t0) || /^Đáp\s*án\s*[:]/i.test(fullT)) ansRaw = (sr.texts[1] || fullT.replace(/^Đáp\s*án\s*[:.]?/i, "")).trim();
                else if (/^Lời\s*giải|Hướng\s*dẫn/i.test(t0)) solHtml = sr.cells[1] || sr.cells[0].replace(/^(Lời\s*giải|Hướng\s*dẫn)\s*[:.]?/i, "").trim();
                else contentRows.push(sr);
              }

              if (col === "green") {
                const opts = contentRows.slice(0, 4).map(sr => {
                  let raw = sr.cells.length >= 2 && (!sr.texts[0] || /^[A-D]\.?$/i.test(sr.texts[0])) ? sr.cells[1] : sr.cells.filter(Boolean).join(" ");
                  return raw.replace(/^(<[^>]+>)*\s*[A-D]\s*[.)]\s*/i, "").replace(/<\/?span[^>]*>/g, "").trim();
                });
                while (opts.length < 4) opts.push("");
                const m = ansRaw.toUpperCase().match(/[A-D]/);
                questions.push({ id: "wq-" + (questions.length + 1), part: 1, text: qHtml, options: opts, answer: m ? "ABCD".indexOf(m[0]) : 0, solution: solHtml });
              } else if (col === "orange") {
                const tfAns = parseTfAnswerString(ansRaw);
                const labels = ["a", "b", "c", "d"];
                const stmts = contentRows.slice(0, 4).map((sr, si) => {
                  let raw = sr.cells.length >= 2 && (!sr.texts[0] || /^[a-d][.)]?$/i.test(sr.texts[0])) ? sr.cells[1] : sr.cells.filter(Boolean).join(" ");
                  raw = raw.replace(/^(<[^>]+>)*\s*[a-d]\s*[.)]\s*/i, "").replace(/<\/?span[^>]*>/g, "").trim();
                  return { label: labels[si], text: raw, answer: !!tfAns[si] };
                });
                while (stmts.length < 4) stmts.push({ label: labels[stmts.length], text: "", answer: false });
                questions.push({ id: "wq-" + (questions.length + 1), part: 2, text: qHtml, statements: stmts, solution: solHtml });
              } else {
                questions.push({ id: "wq-" + (questions.length + 1), part: 3, text: qHtml, answer: normalizeShortAns(ansRaw), solution: solHtml });
              }
            } else i++;
          }
        }
      }
    }

    if (!colorTableFound || questions.length === 0) {
      const parsedText = parseFreeTextNodes(bodyNodes, mediaMap);
      if (parsedText.questions.length > questions.length) {
        questions = parsedText.questions;
        if (!essayParts.length && parsedText.essayHTML) essayParts = [parsedText.essayHTML];
      }
    }
    return { questions, essayHTML: essayParts.join("") };
  }

  function parseFreeTextNodes(bodyNodes, mediaMap) {
    let part = 1, cur = null, inEssay = false, inAnswerKey = false;
    const qs = [], essay = [], answerKeyMap = {};

    const flushCur = () => {
      if (!cur) return;
      if (cur.part === 1) {
        while (cur.options.length < 4) cur.options.push("");
      } else if (cur.part === 2) {
        const labels = ["a", "b", "c", "d"];
        while (cur.statements.length < 4) cur.statements.push({ label: labels[cur.statements.length], text: "", answer: false });
      }
      qs.push(cur);
      cur = null;
    };

    for (const node of bodyNodes) {
      if (node.localName === "tbl") {
        const rows = Array.from(node.children || []).filter(c => c.localName === "tr");
        rows.forEach(tr => {
          const txt = getRowContent(tr, mediaMap).texts.join(" ");
          for (const m of txt.matchAll(/(\d+)\s*[:.\-\s]\s*([A-D])\b/gi)) {
            answerKeyMap[Number(m[1])] = "ABCD".indexOf(m[2].toUpperCase());
          }
        });
        continue;
      }
      if (node.localName !== "p") continue;

      const raw = extractParagraphHtml(node, mediaMap);
      const p = stripTags(raw);
      if (!p && !raw.includes("<img")) continue;

      if (/^(BẢNG\s*ĐÁP\s*ÁN|ĐÁP\s*ÁN\s*CHI\s*TIẾT|HƯỚNG\s*DẪN\s*CHẤM)/i.test(p)) {
        flushCur();
        inAnswerKey = true;
        continue;
      }

      if (inAnswerKey) {
        for (const m of p.matchAll(/(?:Câu\s*)?(\d+)\s*[:.\-\s]\s*([A-D])\b/gi)) {
          answerKeyMap[Number(m[1])] = "ABCD".indexOf(m[2].toUpperCase());
        }
        continue;
      }

      if (/PHẦN\s*TỰ\s*LUẬN|II\.\s*TỰ\s*LUẬN/i.test(p)) { flushCur(); inEssay = true; continue; }
      if (inEssay) { essay.push(`<p>${raw.replace(/<\/?span[^>]*>/g, "")}</p>`); continue; }
      if (/^\[?PH[ẦA]N\s*(1|I)\b/i.test(p)) { flushCur(); part = 1; continue; }
      if (/^\[?PH[ẦA]N\s*(2|II)\b/i.test(p)) { flushCur(); part = 2; continue; }
      if (/^\[?PH[ẦA]N\s*(3|III)\b/i.test(p)) { flushCur(); part = 3; continue; }

      const qStart = p.match(/^(?:Câu|Bài)\s*(\d+)\s*[:.)]\s*(.*)$/i);
      if (qStart) {
        flushCur();
        const qNum = Number(qStart[1]);
        let bodyRaw = raw.replace(/^(?:<[^>]+>|\s)*(?:Câu|Bài)\s*\d+\s*[:.)]\s*/i, "");
        cur = { id: "wq-" + (qs.length + 1), num: qNum, part, text: "", options: [], statements: [], answer: part === 1 ? 0 : "", solution: "" };

        const inline = splitInlineOptions(bodyRaw);
        if (part === 1 && inline) {
          const firstOptPos = bodyRaw.search(/(?:^|>|\s)\*?\s*A\s*[.)]\s*/i);
          cur.text = firstOptPos > 0 ? bodyRaw.slice(0, firstOptPos).replace(/<\/?span[^>]*>/g, "").trim() : "";
          Object.entries(inline.out).forEach(([k, v]) => { cur.options[Number(k)] = v; });
          if (inline.markedIdx >= 0) cur.answer = inline.markedIdx;
        } else {
          cur.text = bodyRaw.replace(/<\/?span[^>]*>/g, "").trim();
        }
        continue;
      }

      if (!cur) continue;
      if (/^\[?L[ỜO]I\s*GI[ẢA]I\]?[:.]?/i.test(p)) { cur.solution = raw.replace(/^.*?L[ỜO]I\s*GI[ẢA]I\]?\s*[:.]?\s*/i, "").replace(/<\/?span[^>]*>/g, ""); continue; }
      if (/^\[?[ĐD][ÁA]P\s*[ÁA]N\]?[:.]?/i.test(p)) {
        const val = p.replace(/^\[?[ĐD][ÁA]P\s*[ÁA]N\]?\s*[:.]?\s*/i, "").trim();
        if (cur.part === 1) { const m = val.toUpperCase().match(/[A-D]/); if (m) cur.answer = "ABCD".indexOf(m[0]); }
        else if (cur.part === 2) { const arr = parseTfAnswerString(val); cur.statements.forEach((st, idx) => { st.answer = !!arr[idx]; }); }
        else cur.answer = normalizeShortAns(val);
        continue;
      }

      if (cur.part === 1) {
        const inline = splitInlineOptions(raw);
        if (inline) {
          Object.entries(inline.out).forEach(([k, v]) => { cur.options[Number(k)] = v; });
          if (inline.markedIdx >= 0) cur.answer = inline.markedIdx;
          continue;
        }
        const mc = p.match(/^(\*)?\s*([A-D])\s*[.)]\s*(.*)$/i);
        if (mc) {
          const idx = "ABCD".indexOf(mc[2].toUpperCase());
          if (mc[1] || raw.includes('data-marked-ans="1"')) cur.answer = idx;
          cur.options[idx] = raw.replace(/^\s*(?:<[^>]+>|\s)*\*?\s*[A-D]\s*[.)]\s*/i, "").replace(/<\/?span[^>]*>/g, "").trim();
          continue;
        }
      }

      const tf = p.match(/^([a-d])\s*[.)]\s*(?:\[(Đ|D|S)\])?\s*(.*)$/i);
      if (cur.part === 2 && tf) {
        const isMarked = raw.includes('data-marked-ans="1"');
        cur.statements.push({
          label: tf[1].toLowerCase(),
          text: raw.replace(/^\s*(?:<[^>]+>|\s)*[a-d]\s*[.)]\s*(\[(Đ|D|S)\])?\s*/i, "").replace(/<\/?span[^>]*>/g, "").trim(),
          answer: tf[2] ? tf[2].toUpperCase() !== "S" : isMarked
        });
        continue;
      }
      cur.text += (cur.text ? "<br/>" : "") + raw.replace(/<\/?span[^>]*>/g, "");
    }
    flushCur();

    qs.forEach((q, idx) => {
      const k = q.num || (idx + 1);
      if (q.part === 1 && answerKeyMap[k] !== undefined) q.answer = answerKeyMap[k];
    });

    return { questions: qs, essayHTML: essay.join("") };
  }

  return { parseDocx };
})();

async function handleWordUpload(e) {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const result = await OriginWordEngine.parseDocx(file);
    state.parsedWordQuestions = result.questions;
    state.parsedEssayHTML = result.essayHTML;

    if (!result.questions.length && !result.essayHTML) {
      document.getElementById("word-preview-area").style.display = "none";
      return showToast("Không tìm thấy câu hỏi nào trong file Word!", "warn");
    }

    document.getElementById("word-preview-area").style.display = "block";
    renderParsedWordEditor();

    const essayBox = document.getElementById("word-essay-preview-box");
    if (result.essayHTML) {
      essayBox.style.display = "block";
      const el = document.getElementById("word-essay-live-preview");
      el.innerHTML = result.essayHTML;
      renderMath(el);
    } else {
      essayBox.style.display = "none";
    }
    showToast(`Đã nhận diện ${result.questions.length} câu hỏi từ file Word!`, "success");
  } catch (err) {
    showToast("Lỗi đọc file Word: " + err.message, "error");
  }
}

function toggleParsedTF(qi, si) {
  state.parsedWordQuestions[qi].statements[si].answer = !state.parsedWordQuestions[qi].statements[si].answer;
  renderParsedWordEditor();
}

function removeParsedQ(i) {
  state.parsedWordQuestions.splice(i, 1);
  if (!state.parsedWordQuestions.length && !state.parsedEssayHTML) {
    document.getElementById("word-preview-area").style.display = "none";
  } else {
    renderParsedWordEditor();
  }
}

async function downloadColorWordTemplate(withEssay = false) {
  if (!window.docx) return showToast("Đang tải thư viện xuất Word, thử lại sau 2 giây.", "warn");
  const { Document, Packer, Paragraph, Table, TableRow, TableCell, WidthType, ShadingType, TextRun } = window.docx;
  const makeRow = (c1, c2, fillHex = null) => new TableRow({
    children: [c1, c2].map((txt, idx) => new TableCell({
      width: { size: idx === 0 ? 18 : 82, type: WidthType.PERCENTAGE },
      shading: fillHex ? { type: ShadingType.CLEAR, color: "auto", fill: fillHex } : undefined,
      children: [new Paragraph({ children: [new TextRun({ text: txt, bold: !!fillHex || txt === "Đáp án" })] })]
    }))
  });

  const rows = [];
  // 20 câu Trắc nghiệm 4 phương án (mẫu chuẩn)
  for (let q = 1; q <= 20; q++) {
    rows.push(makeRow("Câu " + q, "Nhập nội dung câu hỏi trắc nghiệm 4 phương án...", "CCFFCC"));
    rows.push(makeRow("A", "Phương án A"));
    rows.push(makeRow("B", "Phương án B"));
    rows.push(makeRow("C", "Phương án C"));
    rows.push(makeRow("D", "Phương án D"));
    rows.push(makeRow("Đáp án", "A"));
  }
  // 6 câu Đúng/Sai (mẫu chuẩn)
  for (let q = 21; q <= 26; q++) {
    rows.push(makeRow("Câu " + q, "Nhập nội dung câu hỏi Đúng / Sai...", "FBE4D5"));
    rows.push(makeRow("a)", "Mệnh đề a"));
    rows.push(makeRow("b)", "Mệnh đề b"));
    rows.push(makeRow("c)", "Mệnh đề c"));
    rows.push(makeRow("d)", "Mệnh đề d"));
    rows.push(makeRow("Đáp án", "Đ S Đ Đ"));
  }
  // 10 câu Trả lời ngắn (mẫu chuẩn)
  for (let q = 27; q <= 36; q++) {
    rows.push(makeRow("Câu " + q, "Nhập nội dung câu hỏi trả lời ngắn...", "DEEAF6"));
    rows.push(makeRow("Đáp án", "0"));
  }

  const children = [
    new Paragraph({ children: [new TextRun({ text: "ĐỀ KIỂM TRA ORIGIN MATH (20 TN • 6 Đ/S • 10 TLN)", bold: true })] }),
    new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows })
  ];
  if (withEssay) {
    children.push(new Paragraph({ text: "" }), new Paragraph({ children: [new TextRun({ text: "PHẦN TỰ LUẬN", bold: true })] }), new Paragraph({ text: "Bài 1: ..." }));
  }
  const doc = new Document({ sections: [{ children }] });
  triggerDownload(await Packer.toBlob(doc), withEssay ? "OriginMath_Form_TuLuan.docx" : "OriginMath_Form_TracNghiem.docx");
}

function toggleStudioWhitelistBox() {
  const show = document.getElementById("st-access-mode").value === "whitelist";
  document.getElementById("st-whitelist-box").style.display = show ? "block" : "none";
  if (show) renderStudentPicker("st-student-picker", []);
}

async function publishParsedExam() {
  if (!state.parsedWordQuestions.length && !state.parsedEssayHTML) {
    return showToast("Chưa có nội dung đề để xuất bản!", "warn");
  }
  const whitelistRaw = (document.getElementById("st-whitelist-input")?.value || "")
    .split(/[\s,;]+/).map(x => x.trim().toLowerCase()).filter(Boolean);

  const obj = {
    id: "set-" + Date.now(),
    code: (document.getElementById("st-code").value.trim() || "OM-" + Date.now().toString().slice(-4)).toUpperCase(),
    title: document.getElementById("st-title").value.trim() || "Đề Toán Origin Math",
    mode: document.getElementById("st-mode").value,
    grade: document.getElementById("st-grade").value,
    accessMode: document.getElementById("st-access-mode").value,
    allowedStudents: whitelistRaw,
    duration: Number(document.getElementById("st-duration").value) || 60,
    maxViolations: Number(document.getElementById("st-maxviol").value) || 3,
    scoring: {
      p1: Number(document.getElementById("st-p1-pts").value) || 0.25,
      p2: Number(document.getElementById("st-p2-pts").value) || 1.0,
      p3: Number(document.getElementById("st-p3-pts").value) || 0.5,
      scaleMode: document.getElementById("st-scale-mode").value
    },
    questions: JSON.parse(JSON.stringify(state.parsedWordQuestions)),
    essayHTML: state.parsedEssayHTML,
    createdAt: Date.now()
  };

  state.sets.unshift(obj);
  saveAndBroadcast("exam");
  if (isFirebaseLive) await fbDb.collection("exams").doc(obj.id).set(obj).catch(() => {});
  state.parsedWordQuestions = [];
  state.parsedEssayHTML = "";
  document.getElementById("word-preview-area").style.display = "none";
  document.getElementById("word-essay-preview-box").style.display = "none";
  refreshAllViews();
  showToast(`Đã xuất bản "${obj.title}" (${obj.code})`, "success");
}

function switchStudioTab(tab, btn) {
  document.querySelectorAll(".studio-tab").forEach(t => t.classList.remove("active"));
  document.getElementById(`studio-tab-${tab}`).classList.add("active");
  btn.parentElement.querySelectorAll(".pill").forEach(p => p.classList.remove("active"));
  btn.classList.add("active");
  if (tab === "accounts") renderAccountsTable();
  if (tab === "manage") renderManageSetsTable();
  if (tab === "monitor") renderMonitorTable();
}

function renderManageSetsTable() {
  const tbody = document.getElementById("manage-sets-tbody");
  if (!tbody) return;
  tbody.innerHTML = state.sets.length ? state.sets.map(s => {
    const hw = state.handwrittenSolutions[s.id];
    return `<tr>
      <td><strong>${escapeHtml(s.title)}</strong><div class="muted">${escapeHtml(s.code)} • ${s.questions.length} câu</div></td>
      <td><span class="chip chip-primary">${gradeBadgeLabel(s.grade)}</span></td>
      <td>${s.mode === "practice" ? "Luyện đề" : "Khảo thí"}</td>
      <td>${hw && hw.pages?.length ? `<span class="chip chip-success">${hw.pages.length} trang A4</span>` : `<span class="muted">—</span>`}</td>
      <td>
        <div class="action-cell-group">
          <button class="btn btn-ghost btn-xs" onclick="openSetPermissionModal('${s.id}')"><i class="fa-solid fa-user-lock"></i> Quyền</button>
          <button class="btn btn-danger btn-xs" onclick="deleteSet('${s.id}')"><i class="fa-solid fa-trash"></i></button>
        </div>
      </td>
    </tr>`;
  }).join("") : `<tr><td colspan="5" class="muted">Chưa có đề nào.</td></tr>`;
}

function openSetPermissionModal(setId) {
  const s = state.sets.find(x => x.id === setId);
  if (!s) return;
  document.getElementById("result-modal-title").innerHTML = `<i class="fa-solid fa-user-lock"></i> Phân quyền: ${escapeHtml(s.code)}`;
  const body = document.getElementById("result-modal-body");
  body.innerHTML = `
    <div class="field">
      <label>Chế độ quyền vào phòng</label>
      <select id="edit-set-access">
        <option value="grade" ${s.accessMode !== "whitelist" ? "selected" : ""}>Theo Khối / Quyền đã duyệt</option>
        <option value="whitelist" ${s.accessMode === "whitelist" ? "selected" : ""}>Chỉ học sinh được chọn</option>
      </select>
    </div>
    <div class="field">
      <label>Tên đăng nhập học sinh (cách nhau dấu phẩy)</label>
      <input type="text" id="edit-set-whitelist" value="${escapeHtml((s.allowedStudents || []).join(", "))}" />
    </div>
    <div id="edit-set-picker" class="student-picker-grid" style="margin-bottom:14px;"></div>
    <button class="btn btn-primary" onclick="saveSetPermissions('${s.id}')"><i class="fa-solid fa-floppy-disk"></i> Lưu</button>
  `;
  renderStudentPicker("edit-set-picker", s.allowedStudents || [], "edit-set-whitelist");
  document.getElementById("result-modal").style.display = "grid";
}

async function saveSetPermissions(setId) {
  const s = state.sets.find(x => x.id === setId);
  if (!s) return;
  s.accessMode = document.getElementById("edit-set-access").value;
  s.allowedStudents = (document.getElementById("edit-set-whitelist").value || "")
    .split(/[\s,;]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
  saveAndBroadcast("exam");
  if (isFirebaseLive) await fbDb.collection("exams").doc(s.id).set(s, { merge: true }).catch(() => {});
  closeModal("result-modal");
  refreshAllViews();
  showToast("Đã cập nhật phân quyền", "success");
}

async function deleteSet(setId) {
  if (!confirm("Xóa đề này?")) return;
  state.sets = state.sets.filter(s => s.id !== setId);
  delete state.handwrittenSolutions[setId];
  saveAndBroadcast("exam");
  if (isFirebaseLive) await fbDb.collection("exams").doc(setId).delete().catch(() => {});
  refreshAllViews();
  showToast("Đã xóa đề", "info");
}

function getUserAvatar(uid) {
  return (state.usersMap[uid] && state.usersMap[uid].avatar) || getDefaultAvatar("Nam");
}

function renderHistory() {
  const curUid = state.user ? state.user.uid : "guest-local";
  const mySubs = state.submissions.filter(s => s.uid === curUid);
  document.getElementById("history-tbody").innerHTML = mySubs.length ? mySubs.map(s => `
    <tr>
      <td><strong>${escapeHtml(s.examTitle)}</strong><div class="muted">${new Date(s.submittedAt).toLocaleString("vi-VN")}</div></td>
      <td><span class="chip ${s.mode === 'exam' ? 'chip-primary' : 'chip-success'}">${s.mode === "exam" ? "Khảo thí" : "Luyện đề"}</span></td>
      <td><strong style="color:var(--primary);font-size:15px;">${s.score}</strong></td>
      <td>
        <div class="action-cell-group">
          <button class="btn btn-ghost btn-xs" onclick="openSavedSubmission('${s.id}')"><i class="fa-regular fa-eye"></i> Xem lại</button>
          ${s.mode === "practice" ? `<button class="btn btn-warning btn-xs" onclick="startPractice('${s.examId}')"><i class="fa-solid fa-wrench"></i> Sửa sai</button>` : ""}
        </div>
      </td>
    </tr>
  `).join("") : `<tr><td colspan="4" class="muted">Chưa có lịch sử làm bài.</td></tr>`;

  const bestMap = {};
  state.submissions.forEach(s => {
    const sc = Number(s.score || 0);
    if (!bestMap[s.uid] || sc > bestMap[s.uid].score) {
      bestMap[s.uid] = { uid: s.uid, name: (state.usersMap[s.uid]?.name || s.studentName), score: sc };
    }
  });
  const sorted = Object.values(bestMap).sort((a, b) => b.score - a.score).slice(0, 10);
  document.getElementById("leaderboard-list").innerHTML = sorted.length ? sorted.map((x, i) => `
    <div class="lb-item">
      <div class="lb-rank">${i + 1}</div>
      <img src="${getUserAvatar(x.uid)}" alt=""/>
      <strong>${escapeHtml(x.name)}</strong>
      <div class="lb-score">${x.score} đ</div>
    </div>`).join("") : `<p class="muted">Chưa có dữ liệu.</p>`;
}

function openSavedSubmission(subId) {
  const sub = state.submissions.find(s => s.id === subId);
  if (!sub) return;
  showSubmissionResultModal(sub);
}

function renderMonitorTable() {
  const tbody = document.getElementById("monitor-tbody");
  if (!tbody) return;
  tbody.innerHTML = state.participants.length ? state.participants.map(p => `
    <tr>
      <td><div class="user-cell"><img src="${getUserAvatar(p.uid)}" alt=""/><strong>${escapeHtml(state.usersMap[p.uid]?.name || p.studentName)}</strong></div></td>
      <td>${escapeHtml(p.examTitle)}</td>
      <td>Khảo thí</td>
      <td><strong style="color:var(--primary)">${p.score}</strong></td>
      <td>${p.violations}</td>
      <td><span class="chip ${p.status === 'Bị truất quyền thi' ? 'chip-danger' : 'chip-primary'}">${escapeHtml(p.status)}</span></td>
    </tr>`).join("") : `<tr><td colspan="6" class="muted">Chưa có thí sinh tham gia.</td></tr>`;
}

function compressImageFile(file, maxDim = 1000, quality = 0.82) {
  return new Promise((resolve) => {
    const r = new FileReader();
    r.onload = () => {
      const img = new Image();
      img.onload = () => {
        const scale = Math.min(1, maxDim / Math.max(img.width, img.height));
        const c = document.createElement("canvas");
        c.width = Math.round(img.width * scale);
        c.height = Math.round(img.height * scale);
        c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
        resolve(c.toDataURL("image/jpeg", quality));
      };
      img.src = r.result;
    };
    r.readAsDataURL(file);
  });
}

function openImageZoomModal(src) {
  let ov = document.getElementById("img-zoom-lightbox");
  if (!ov) {
    ov = document.createElement("div");
    ov.id = "img-zoom-lightbox";
    ov.style.cssText = "position:fixed;inset:0;z-index:12000;background:rgba(15,23,42,0.9);display:grid;place-items:center;padding:20px;cursor:zoom-out;";
    ov.onclick = () => { ov.style.display = "none"; };
    ov.innerHTML = `<img id="img-zoom-target" style="max-width:95vw;max-height:92vh;border-radius:12px;box-shadow:0 20px 50px rgba(0,0,0,0.6);" alt="Phóng to"/>`;
    document.body.appendChild(ov);
  }
  document.getElementById("img-zoom-target").src = src;
  ov.style.display = "grid";
}

function exportResultsCSV() {
  const lines = ["HocSinh,DeThi,Diem,ViPham,TrangThai"];
  state.participants.forEach(p => lines.push(`"${state.usersMap[p.uid]?.name || p.studentName}","${p.examTitle}",${p.score},${p.violations},"${p.status}"`));
  triggerDownload(new Blob(["\uFEFF" + lines.join("\n")], { type: "text/csv;charset=utf-8;" }), `OriginMath_KetQua_${Date.now()}.csv`);
}

function triggerDownload(blob, name) {
  const url = URL.createObjectURL(blob), a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function initWordDropzone() {
  const dz = document.getElementById("word-dropzone");
  if (!dz) return;
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("dragover"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("dragover"));
  dz.addEventListener("drop", (e) => {
    e.preventDefault(); dz.classList.remove("dragover");
    const f = e.dataTransfer.files[0];
    if (f && f.name.toLowerCase().endsWith(".docx")) handleWordUpload({ target: { files: [f] } });
    else showToast("Vui lòng chọn tệp .docx", "warn");
  });
}

// ---------------- LỐI TẮT ỨNG DỤNG (ĐIỆN THOẠI IOS / ANDROID & MÁY TÍNH) ----------------
function openShortcutGuideModal() {
  const ua = navigator.userAgent || "";
  const isIOS = /iPad|iPhone|iPod/.test(ua);
  const isAndroid = /Android/.test(ua);
  const platformName = isIOS ? "iPhone / iPad (iOS)" : isAndroid ? "Điện thoại Android" : "Máy tính / Laptop";

  document.getElementById("result-modal-title").innerHTML = `<i class="fa-solid fa-mobile-screen-button"></i> Tạo lối tắt như ứng dụng (${platformName})`;
  document.getElementById("result-modal-body").innerHTML = `
    <div style="display:flex;flex-direction:column;gap:12px;font-size:13.5px;line-height:1.6;">
      <div class="scoring-box" style="margin-bottom:0;">
        <strong><i class="fa-brands fa-apple"></i> Trên iPhone / iPad (Safari):</strong>
        <div style="margin-top:4px;">Nhấn biểu tượng <strong>Chia sẻ</strong> (ô vuông có mũi tên lên) → chọn <strong>Thêm vào MH chính</strong> (Add to Home Screen) → nhấn <strong>Thêm</strong>.</div>
      </div>
      <div class="scoring-box" style="margin-bottom:0;">
        <strong><i class="fa-brands fa-android"></i> Trên điện thoại Android (Chrome):</strong>
        <div style="margin-top:4px;">Nhấn nút <strong>⋮</strong> ở góc trên bên phải → chọn <strong>Thêm vào màn hình chính</strong> hoặc <strong>Cài đặt ứng dụng</strong>.</div>
      </div>
      <div class="scoring-box" style="margin-bottom:0;">
        <strong><i class="fa-solid fa-laptop"></i> Trên Laptop / Máy tính (Chrome / Edge):</strong>
        <div style="margin-top:4px;">Nhấn biểu tượng <strong>⋮</strong> (hoặc biểu tượng cài đặt trên thanh địa chỉ) → <strong>Lưu và chia sẻ</strong> / <strong>Ứng dụng</strong> → <strong>Tạo lối tắt</strong> (tích <em>Mở dưới dạng cửa sổ</em> để chạy như app riêng).</div>
      </div>
    </div>
  `;
  document.getElementById("result-modal").style.display = "grid";
}

// ---------------- SCRBLE INK V2.5 — BẢNG VIẾT A4 ĐẦY ĐỦ 5 BÚT, 2 TẨY (TRÒN), CHỌN VÙNG CẮT/NHÂN BẢN/XÓA, LASER NÉT LIỀN TẠM THỜI ----------------
const wbState = {
  ready: false,
  bgCanvas: null, bgCtx: null,
  mainCanvas: null, mainCtx: null,
  laserCanvas: null, laserCtx: null,
  tool: "calligraphy",
  color: "#1d4ed8",
  bgMode: "grid",
  drawing: false,
  startX: 0, startY: 0,
  points: [],
  strokes: [], // Lưu từng đối tượng nét vẽ / hình / ảnh / văn bản để tẩy từng đường hoặc chọn vùng thao tác
  pages: [],
  pageIdx: 0,
  redoStack: [],
  laserStrokes: [],
  laserActive: false,
  selectedBox: null, // { x, y, w, h, imgData }
  pendingTextPos: null
};

function drawA4PaperPattern(ctx, w, h, mode) {
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, w, h);

  if (mode === "grid") {
    const step = 31;
    ctx.strokeStyle = "rgba(148, 163, 184, 0.28)";
    ctx.lineWidth = 1;
    for (let x = step; x < w; x += step) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
    for (let y = step; y < h; y += step) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
  } else if (mode === "lined") {
    const lineGap = 38;
    ctx.strokeStyle = "rgba(59, 130, 246, 0.24)";
    ctx.lineWidth = 1.1;
    for (let y = 68; y < h - 30; y += lineGap) { ctx.beginPath(); ctx.moveTo(42, y); ctx.lineTo(w - 42, y); ctx.stroke(); }
    ctx.strokeStyle = "rgba(239, 68, 68, 0.35)";
    ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.moveTo(96, 24); ctx.lineTo(96, h - 24); ctx.stroke();
  } else if (mode === "oxy") {
    const step = 31;
    ctx.strokeStyle = "rgba(148, 163, 184, 0.22)";
    ctx.lineWidth = 1;
    for (let x = step; x < w; x += step) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
    for (let y = step; y < h; y += step) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
    const cx = Math.round(w / 2 / step) * step;
    const cy = Math.round(h / 2 / step) * step;
    ctx.strokeStyle = "#334155";
    ctx.fillStyle = "#334155";
    ctx.lineWidth = 2.2;
    ctx.beginPath(); ctx.moveTo(40, cy); ctx.lineTo(w - 40, cy); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(w - 40, cy); ctx.lineTo(w - 52, cy - 6); ctx.lineTo(w - 52, cy + 6); ctx.closePath(); ctx.fill();
    ctx.beginPath(); ctx.moveTo(cx, h - 40); ctx.lineTo(cx, 40); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(cx, 40); ctx.lineTo(cx - 6, 52); ctx.lineTo(cx + 6, 52); ctx.closePath(); ctx.fill();
    ctx.lineWidth = 1.4;
    for (let x = cx + step; x < w - 55; x += step) { ctx.beginPath(); ctx.moveTo(x, cy - 4); ctx.lineTo(x, cy + 4); ctx.stroke(); }
    for (let x = cx - step; x > 55; x -= step) { ctx.beginPath(); ctx.moveTo(x, cy - 4); ctx.lineTo(x, cy + 4); ctx.stroke(); }
    for (let y = cy + step; y < h - 55; y += step) { ctx.beginPath(); ctx.moveTo(cx - 4, y); ctx.lineTo(cx + 4, y); ctx.stroke(); }
    for (let y = cy - step; y > 55; y -= step) { ctx.beginPath(); ctx.moveTo(cx - 4, y); ctx.lineTo(cx + 4, y); ctx.stroke(); }
    ctx.font = "italic 700 18px 'Be Vietnam Pro', serif";
    ctx.fillText("O", cx - 20, cy + 20);
    ctx.fillText("x", w - 48, cy + 22);
    ctx.fillText("y", cx + 14, 52);
  }
}

function drawMathShape(ctx, tool, x1, y1, x2, y2, color, size) {
  ctx.save();
  ctx.strokeStyle = color; ctx.fillStyle = color; ctx.lineWidth = size;
  ctx.lineCap = "round"; ctx.lineJoin = "round";
  if (tool === "line") {
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
  } else if (tool === "dashed") {
    ctx.setLineDash([10, 7]);
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
  } else if (tool === "arrow") {
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
    const ang = Math.atan2(y2 - y1, x2 - x1), head = 12 + size * 1.5;
    ctx.beginPath(); ctx.moveTo(x2, y2);
    ctx.lineTo(x2 - head * Math.cos(ang - Math.PI / 6), y2 - head * Math.sin(ang - Math.PI / 6));
    ctx.lineTo(x2 - head * Math.cos(ang + Math.PI / 6), y2 - head * Math.sin(ang + Math.PI / 6));
    ctx.closePath(); ctx.fill();
  } else if (tool === "rect") {
    ctx.strokeRect(x1, y1, x2 - x1, y2 - y1);
  } else if (tool === "double-arrow") {
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
    const ang = Math.atan2(y2 - y1, x2 - x1), head = 12 + size * 1.5;
    ctx.beginPath(); ctx.moveTo(x2, y2);
    ctx.lineTo(x2 - head * Math.cos(ang - Math.PI / 6), y2 - head * Math.sin(ang - Math.PI / 6));
    ctx.lineTo(x2 - head * Math.cos(ang + Math.PI / 6), y2 - head * Math.sin(ang + Math.PI / 6));
    ctx.closePath(); ctx.fill();
    ctx.beginPath(); ctx.moveTo(x1, y1);
    ctx.lineTo(x1 + head * Math.cos(ang - Math.PI / 6), y1 + head * Math.sin(ang - Math.PI / 6));
    ctx.lineTo(x1 + head * Math.cos(ang + Math.PI / 6), y1 + head * Math.sin(ang + Math.PI / 6));
    ctx.closePath(); ctx.fill();
  } else if (tool === "circle") {
    const rad = Math.max(1, Math.hypot(x2 - x1, y2 - y1) / 2);
    ctx.beginPath(); ctx.arc((x1 + x2) / 2, (y1 + y2) / 2, rad, 0, Math.PI * 2); ctx.stroke();
  } else if (tool === "ellipse") {
    const rx = Math.abs(x2 - x1) / 2, ry = Math.abs(y2 - y1) / 2;
    ctx.beginPath(); ctx.ellipse((x1 + x2) / 2, (y1 + y2) / 2, Math.max(1, rx), Math.max(1, ry), 0, 0, Math.PI * 2); ctx.stroke();
  } else if (tool === "diamond") {
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    ctx.beginPath(); ctx.moveTo(mx, y1); ctx.lineTo(x2, my); ctx.lineTo(mx, y2); ctx.lineTo(x1, my); ctx.closePath(); ctx.stroke();
  } else if (tool === "triangle") {
    const topX = (x1 + x2) / 2;
    ctx.beginPath(); ctx.moveTo(topX, y1); ctx.lineTo(x1, y2); ctx.lineTo(x2, y2); ctx.closePath(); ctx.stroke();
  } else if (tool === "right-triangle") {
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x1, y2); ctx.lineTo(x2, y2); ctx.closePath(); ctx.stroke();
    ctx.strokeRect(x1, y2 - 12, 12, 12);
  } else if (tool === "axis-xy") {
    const cx = (x1 + x2) / 2, cy = (y1 + y2) / 2;
    ctx.beginPath(); ctx.moveTo(x1, cy); ctx.lineTo(x2, cy); ctx.moveTo(cx, y2); ctx.lineTo(cx, y1); ctx.stroke();
    ctx.font = "italic 700 18px 'Be Vietnam Pro', sans-serif";
    ctx.fillText("O", cx - 18, cy + 18);
    ctx.fillText("x", x2 - 14, cy + 18);
    ctx.fillText("y", cx + 10, y1 + 14);
  }
  ctx.restore();
}


const PEN_ICON_CLASS = {
  calligraphy: "fa-solid fa-feather-pointed",
  pen: "fa-solid fa-pen",
  fountain: "fa-solid fa-pen-nib",
  brush: "fa-solid fa-paintbrush",
  marker: "fa-solid fa-marker"
};

function drawSinglePathSegment(ctx, penType, pts, idx, color, size) {
  if (!pts || idx < 0 || idx >= pts.length) return;
  const p = pts[idx];
  if (idx === 0) {
    ctx.save();
    ctx.fillStyle = color;
    ctx.globalAlpha = penType === "highlighter" ? 0.28 : 1;
    const r = penType === "highlighter" ? size * 2.6 : penType === "marker" ? size * 1.05 : size * 0.52;
    ctx.beginPath();
    ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
    return;
  }

  const prev = pts[idx - 1];
  ctx.save();
  ctx.strokeStyle = color;
  ctx.lineCap = penType === "marker" ? "square" : "round";
  ctx.lineJoin = "round";

  if (penType === "calligraphy") {
    if (idx >= 2) {
      const p0 = pts[idx - 2], p1 = prev, p2 = p;
      const dist = Math.hypot(p2.x - p0.x, p2.y - p0.y);
      const dt = Math.max(1, (p2.t || 0) - (p0.t || 0));
      const factor = Math.max(0.55, Math.min(1.42, 1.28 - (dist / dt) * 0.22));
      ctx.lineWidth = size * factor;
      ctx.beginPath();
      ctx.moveTo((p0.x + p1.x) / 2, (p0.y + p1.y) / 2);
      ctx.quadraticCurveTo(p1.x, p1.y, (p1.x + p2.x) / 2, (p1.y + p2.y) / 2);
      ctx.stroke();
    } else {
      ctx.lineWidth = size;
      ctx.beginPath();
      ctx.moveTo(prev.x, prev.y);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
    }
  } else if (penType === "brush") {
    ctx.lineWidth = size * 1.45;
    ctx.beginPath();
    ctx.moveTo(prev.x, prev.y);
    ctx.lineTo(p.x, p.y);
    ctx.stroke();
    ctx.globalAlpha = 0.24;
    ctx.lineWidth = size * 2.2;
    ctx.beginPath();
    ctx.moveTo(prev.x, prev.y);
    ctx.lineTo(p.x, p.y);
    ctx.stroke();
  } else if (penType === "fountain") {
    const slopeUp = (p.y - prev.y) < 0;
    ctx.lineWidth = slopeUp ? size * 0.65 : size * 1.25;
    ctx.beginPath();
    ctx.moveTo(prev.x, prev.y);
    ctx.lineTo(p.x, p.y);
    ctx.stroke();
  } else if (penType === "marker") {
    ctx.lineWidth = size * 2.1;
    ctx.beginPath();
    ctx.moveTo(prev.x, prev.y);
    ctx.lineTo(p.x, p.y);
    ctx.stroke();
  } else if (penType === "highlighter") {
    ctx.globalAlpha = 0.28;
    ctx.lineWidth = size * 5.2;
    ctx.beginPath();
    ctx.moveTo(prev.x, prev.y);
    ctx.lineTo(p.x, p.y);
    ctx.stroke();
  } else {
    ctx.lineWidth = size;
    ctx.beginPath();
    ctx.moveTo(prev.x, prev.y);
    ctx.lineTo(p.x, p.y);
    ctx.stroke();
  }
  ctx.restore();
}

function redrawMainFromStrokes() {
  if (!wbState.ready) return;
  const ctx = wbState.mainCtx;
  ctx.clearRect(0, 0, wbState.mainCanvas.width, wbState.mainCanvas.height);

  for (const st of wbState.strokes) {
    if (st.kind === "path") {
      const pts = st.pts || [];
      for (let i = 0; i < pts.length; i++) {
        drawSinglePathSegment(ctx, st.penType, pts, i, st.color, st.size);
      }
    } else if (st.kind === "shape") {
      drawMathShape(ctx, st.shape, st.x1, st.y1, st.x2, st.y2, st.color, st.size);
    } else if (st.kind === "text") {
      ctx.save();
      ctx.fillStyle = st.color;
      ctx.font = `700 ${st.fontPx}px 'Be Vietnam Pro', sans-serif`;
      ctx.fillText(st.text, st.x, st.y + st.fontPx * 0.8);
      ctx.restore();
    } else if (st.kind === "image" && st.imgEl) {
      ctx.drawImage(st.imgEl, st.x, st.y, st.w, st.h);
    }
  }
}

function renderLaserOverlay(curPos = null, eraserCircle = null) {
  if (!wbState.ready) return;
  const ctx = wbState.laserCtx;
  ctx.clearRect(0, 0, wbState.laserCanvas.width, wbState.laserCanvas.height);

  if (wbState.laserStrokes && wbState.laserStrokes.length > 0) {
    for (const strokePts of wbState.laserStrokes) {
      if (!strokePts || !strokePts.length) continue;
      ctx.save();
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.strokeStyle = "#ef4444";
      ctx.shadowColor = "#ff1e42";
      ctx.shadowBlur = 12;
      ctx.lineWidth = 5.5;
      ctx.beginPath();
      ctx.moveTo(strokePts[0].x, strokePts[0].y);
      for (let i = 1; i < strokePts.length; i++) ctx.lineTo(strokePts[i].x, strokePts[i].y);
      ctx.stroke();

      ctx.shadowBlur = 2;
      ctx.strokeStyle = "#fff1f2";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(strokePts[0].x, strokePts[0].y);
      for (let i = 1; i < strokePts.length; i++) ctx.lineTo(strokePts[i].x, strokePts[i].y);
      ctx.stroke();
      ctx.restore();
    }
  }

  if (eraserCircle) {
    ctx.save();
    ctx.strokeStyle = "#dc2626";
    ctx.fillStyle = "rgba(239, 68, 68, 0.14)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(eraserCircle.x, eraserCircle.y, eraserCircle.r, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
    ctx.restore();
  }

  if (curPos && wbState.tool === "laser" && (!wbState.laserStrokes || wbState.laserStrokes.length === 0)) {
    ctx.save();
    ctx.fillStyle = "rgba(239,68,68,0.65)";
    ctx.beginPath();
    ctx.arc(curPos.x, curPos.y, 4, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
  }
}

function clearLaserLayer() {
  wbState.laserStrokes = [];
  wbState.laserActive = false;
  if (wbState.ready) wbState.laserCtx.clearRect(0, 0, wbState.laserCanvas.width, wbState.laserCanvas.height);
}

function pointToSegmentDist(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1, dy = y2 - y1;
  const lenSq = dx * dx + dy * dy;
  if (lenSq === 0) return Math.hypot(px - x1, py - y1);
  let t = ((px - x1) * dx + (py - y1) * dy) / lenSq;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
}

function eraseWholeStrokeAt(x, y, radius) {
  let removed = false;
  wbState.strokes = wbState.strokes.filter(st => {
    if (st.kind === "path") {
      const pts = st.pts || [];
      for (let i = 1; i < pts.length; i++) {
        if (pointToSegmentDist(x, y, pts[i - 1].x, pts[i - 1].y, pts[i].x, pts[i].y) <= radius + (st.size || 3)) {
          removed = true;
          return false;
        }
      }
      if (pts.length === 1 && Math.hypot(x - pts[0].x, y - pts[0].y) <= radius + 6) {
        removed = true;
        return false;
      }
      return true;
    }
    if (st.kind === "shape") {
      const d = pointToSegmentDist(x, y, st.x1, st.y1, st.x2, st.y2);
      const minX = Math.min(st.x1, st.x2), maxX = Math.max(st.x1, st.x2);
      const minY = Math.min(st.y1, st.y2), maxY = Math.max(st.y1, st.y2);
      const insideBox = x >= minX - radius && x <= maxX + radius && y >= minY - radius && y <= maxY + radius;
      if (d <= radius + 6 || insideBox) {
        removed = true;
        return false;
      }
      return true;
    }
    if (st.kind === "image" || st.kind === "text") {
      const w = st.w || 180, h = st.h || 32;
      if (x >= st.x - radius && x <= st.x + w + radius && y >= st.y - radius && y <= st.y + h + radius) {
        removed = true;
        return false;
      }
      return true;
    }
    return true;
  });
  if (removed) {
    redrawMainFromStrokes();
    wbSaveCurrentPageSnapshot();
  }
}

function eraseDetailSegmentAt(x, y, radius) {
  const nextStrokes = [];
  let changed = false;
  for (const st of wbState.strokes) {
    if (st.kind === "path") {
      const pts = st.pts || [];
      let curSeg = [];
      for (const p of pts) {
        if (Math.hypot(p.x - x, p.y - y) <= radius) {
          changed = true;
          if (curSeg.length >= 2) nextStrokes.push({ ...st, pts: curSeg });
          curSeg = [];
        } else {
          curSeg.push(p);
        }
      }
      if (curSeg.length >= 2) nextStrokes.push({ ...st, pts: curSeg });
    } else {
      nextStrokes.push(st);
    }
  }
  if (changed) {
    wbState.strokes = nextStrokes;
    redrawMainFromStrokes();
    wbSaveCurrentPageSnapshot();
  }
}

function initTeacherWhiteboardOnce() {
  const stack = document.getElementById("wb-canvas-stack");
  const mainC = document.getElementById("teacher-whiteboard");
  const laserC = document.getElementById("teacher-laser-canvas");
  if (!stack || !mainC || !laserC) return;

  let bgC = document.getElementById("teacher-bg-canvas");
  if (!bgC) {
    bgC = document.createElement("canvas");
    bgC.id = "teacher-bg-canvas";
    bgC.width = mainC.width;
    bgC.height = mainC.height;
    stack.insertBefore(bgC, mainC);
  }

  wbState.ready = true;
  wbState.bgCanvas = bgC;
  wbState.bgCtx = bgC.getContext("2d");
  wbState.mainCanvas = mainC;
  wbState.mainCtx = mainC.getContext("2d");
  wbState.laserCanvas = laserC;
  wbState.laserCtx = laserC.getContext("2d");

  drawA4PaperPattern(wbState.bgCtx, bgC.width, bgC.height, wbState.bgMode);
  wbInitPagesForCurrentSet();

  if (laserC.dataset.wbBound === "1") return;
  laserC.dataset.wbBound = "1";

  const getPos = (e) => {
    const r = laserC.getBoundingClientRect();
    const pt = e.touches ? e.touches[0] : e;
    return {
      x: (pt.clientX - r.left) * (laserC.width / r.width),
      y: (pt.clientY - r.top) * (laserC.height / r.height),
      clientX: pt.clientX,
      clientY: pt.clientY,
      t: performance.now()
    };
  };

  const onDown = (e) => {
    e.preventDefault();
    const p = getPos(e);
    const size = Number(document.getElementById("wb-size")?.value || 3.8);

    if (wbState.tool === "text") {
      openWbTextEditorAt(p.clientX, p.clientY, p.x, p.y);
      return;
    }

    if (wbState.tool === "laser") {
      wbState.drawing = true;
      wbState.laserActive = true;
      wbState.laserStrokes.push([p]);
      renderLaserOverlay(p);
      return;
    }

    if (wbState.tool === "eraser-stroke") {
      wbState.drawing = true;
      eraseWholeStrokeAt(p.x, p.y, 24);
      renderLaserOverlay(null, { x: p.x, y: p.y, r: 24 });
      return;
    }

    if (wbState.tool === "eraser-detail") {
      wbState.drawing = true;
      eraseDetailSegmentAt(p.x, p.y, 20);
      renderLaserOverlay(null, { x: p.x, y: p.y, r: 20 });
      return;
    }

    wbState.drawing = true;
    wbState.startX = p.x;
    wbState.startY = p.y;
    wbState.points = [p];

    if (["calligraphy", "pen", "brush", "fountain", "marker", "highlighter"].includes(wbState.tool)) {
      const stroke = {
        kind: "path",
        penType: wbState.tool,
        color: wbState.color,
        size,
        pts: [p]
      };
      wbState.strokes.push(stroke);
      drawSinglePathSegment(wbState.mainCtx, stroke.penType, stroke.pts, 0, stroke.color, stroke.size);
    }
  };

  const onMove = (e) => {
    const p = getPos(e);
    if (wbState.tool === "eraser-stroke" || wbState.tool === "eraser-detail") {
      const r = wbState.tool === "eraser-stroke" ? 24 : 20;
      if (wbState.drawing) {
        if (wbState.tool === "eraser-stroke") eraseWholeStrokeAt(p.x, p.y, r);
        else eraseDetailSegmentAt(p.x, p.y, r);
      }
      renderLaserOverlay(null, { x: p.x, y: p.y, r });
      return;
    }

    if (!wbState.drawing) return;
    e.preventDefault();
    const size = Number(document.getElementById("wb-size")?.value || 3.8);

    if (wbState.tool === "laser") {
      const curL = wbState.laserStrokes[wbState.laserStrokes.length - 1];
      if (curL) curL.push(p);
      renderLaserOverlay(p);
      return;
    }

    if (["calligraphy", "pen", "brush", "fountain", "marker", "highlighter"].includes(wbState.tool)) {
      const curStroke = wbState.strokes[wbState.strokes.length - 1];
      if (curStroke && curStroke.kind === "path") {
        const lastP = curStroke.pts[curStroke.pts.length - 1];
        if (lastP && Math.hypot(p.x - lastP.x, p.y - lastP.y) < 0.8) return;
        curStroke.pts.push(p);
        drawSinglePathSegment(wbState.mainCtx, curStroke.penType, curStroke.pts, curStroke.pts.length - 1, curStroke.color, curStroke.size);
      }
    } else {
      const snapped = e.shiftKey ? snapAnglePoint(wbState.startX, wbState.startY, p.x, p.y) : p;
      wbState.points.push(snapped);
      renderLaserOverlay();
      drawMathShape(wbState.laserCtx, wbState.tool, wbState.startX, wbState.startY, snapped.x, snapped.y, wbState.color, size);
    }
  };

  const onUp = () => {
    if (!wbState.drawing) return;
    wbState.drawing = false;
    const size = Number(document.getElementById("wb-size")?.value || 3.8);
    const lastPt = wbState.points[wbState.points.length - 1] || { x: wbState.startX, y: wbState.startY };

    if (wbState.tool === "laser") {
      return;
    }

    if (["line", "dashed", "arrow", "double-arrow", "rect", "circle", "ellipse", "diamond", "triangle", "right-triangle", "axis-xy"].includes(wbState.tool)) {
      const sh = {
        kind: "shape",
        shape: wbState.tool,
        x1: wbState.startX,
        y1: wbState.startY,
        x2: lastPt.x,
        y2: lastPt.y,
        color: wbState.color,
        size
      };
      wbState.strokes.push(sh);
      renderLaserOverlay();
      drawMathShape(wbState.mainCtx, sh.shape, sh.x1, sh.y1, sh.x2, sh.y2, sh.color, sh.size);
      wbSaveCurrentPageSnapshot();
    } else if (["calligraphy", "pen", "brush", "fountain", "marker", "highlighter"].includes(wbState.tool)) {
      wbSaveCurrentPageSnapshot();
    }
    wbState.points = [];
  };

  laserC.addEventListener("mousedown", onDown);
  window.addEventListener("mousemove", onMove);
  window.addEventListener("mouseup", onUp);
  laserC.addEventListener("touchstart", onDown, { passive: false });
  laserC.addEventListener("touchmove", onMove, { passive: false });
  window.addEventListener("touchend", onUp);
}

function clearAllScrbleToolHighlights() {
  document.querySelectorAll(".scrble-topbar .active, .scrble-topbar .wb-btn, .scrble-pen-circle, .scrble-icon-btn, .scrble-hl-btn, .scrble-laser-circle").forEach(el => {
    el.classList.remove("active");
  });
}

function setWbTool(tool, btn) {
  const prevTool = wbState.tool;
  wbState.tool = tool;
  clearAllScrbleToolHighlights();
  if (btn) btn.classList.add("active");

  if (prevTool === "laser" && tool !== "laser") {
    clearLaserLayer();
  } else {
    renderLaserOverlay();
  }
}

function setWbShapeTool(shapeVal) {
  if (!shapeVal || shapeVal === "none") return;
  if (wbState.tool === "laser") clearLaserLayer();
  wbState.tool = shapeVal;
  clearAllScrbleToolHighlights();
  document.getElementById("scrble-shapes-btn")?.classList.add("active");
}

function setWbColor(col, btn) {
  wbState.color = col;
  document.querySelectorAll(".wb-color").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");

  const mainBtn = document.getElementById("scrble-pen-main-btn");
  if (mainBtn) {
    mainBtn.style.background = col;
    mainBtn.style.color = col.toLowerCase() === "#ffffff" ? "#0f172a" : "#ffffff";
  }
  const wave = document.getElementById("scrble-wave-path");
  if (wave) wave.setAttribute("stroke", col);

  const activePen = wbState.activePenType || "calligraphy";
  setWbTool(activePen, mainBtn);
}

function setWbBgMode(mode) {
  wbState.bgMode = mode;
  if (wbState.ready && wbState.bgCtx) drawA4PaperPattern(wbState.bgCtx, wbState.bgCanvas.width, wbState.bgCanvas.height, mode);
}

function wbInitPagesForCurrentSet() {
  if (!wbState.ready) return;
  wbState.pages = [{ strokes: [], dataUrl: "" }];
  wbState.pageIdx = 0;
  wbState.strokes = [];
  wbState.redoStack = [];
  clearLaserLayer();
  redrawMainFromStrokes();
  wbUpdatePageLabel();
}

function wbSaveCurrentPageSnapshot() {
  if (!wbState.ready) return;
  wbState.pages[wbState.pageIdx] = {
    strokes: [...wbState.strokes],
    dataUrl: wbState.mainCanvas.toDataURL()
  };
}

function wbLoadPage(idx) {
  if (!wbState.ready) return;
  wbState.pageIdx = Math.max(0, Math.min(wbState.pages.length - 1, idx));
  const pg = wbState.pages[wbState.pageIdx] || { strokes: [] };
  wbState.strokes = [...(pg.strokes || [])];
  redrawMainFromStrokes();
  renderLaserOverlay();
  wbUpdatePageLabel();
}

function wbAddPage() {
  if (!wbState.ready) return;
  wbSaveCurrentPageSnapshot();
  wbState.pages.push({ strokes: [], dataUrl: "" });
  wbLoadPage(wbState.pages.length - 1);
  showToast(`Đã thêm trang A4 thứ ${wbState.pages.length}`, "info");
}

function wbPrevPage() {
  if (wbState.pageIdx <= 0) return;
  wbSaveCurrentPageSnapshot();
  wbLoadPage(wbState.pageIdx - 1);
}

function wbNextPage() {
  if (wbState.pageIdx >= wbState.pages.length - 1) return;
  wbSaveCurrentPageSnapshot();
  wbLoadPage(wbState.pageIdx + 1);
}

function wbUpdatePageLabel() {
  const lbl = document.getElementById("wb-page-label");
  if (lbl) lbl.textContent = `(${wbState.pageIdx + 1}/${wbState.pages.length})`;
}

function wbUndo() {
  if (!wbState.ready || !wbState.strokes.length) return;
  wbState.redoStack.push(wbState.strokes.pop());
  redrawMainFromStrokes();
  wbSaveCurrentPageSnapshot();
}

function wbRedo() {
  if (!wbState.ready || !wbState.redoStack.length) return;
  wbState.strokes.push(wbState.redoStack.pop());
  redrawMainFromStrokes();
  wbSaveCurrentPageSnapshot();
}

function clearWhiteboard() {
  if (!wbState.ready) return;
  wbState.strokes = [];
  wbState.redoStack = [];
  clearLaserLayer();
  redrawMainFromStrokes();
  wbSaveCurrentPageSnapshot();
}

function toggleWbFullscreen() {
  document.getElementById("teacher-board-wrap")?.classList.toggle("wb-fullscreen");
}

function drawImageOntoBoard(dataUrl) {
  if (!wbState.ready) return;
  const img = new Image();
  img.onload = () => {
    const c = wbState.mainCanvas;
    const scale = Math.min(1, (c.width * 0.65) / img.width, (c.height * 0.55) / img.height);
    const w = Math.round(img.width * scale);
    const h = Math.round(img.height * scale);
    const x = Math.round((c.width - w) / 2);
    const y = Math.round((c.height - h) / 2);
    wbState.strokes.push({ kind: "image", imgEl: img, x, y, w, h });
    wbState.mainCtx.drawImage(img, x, y, w, h);
    wbSaveCurrentPageSnapshot();
    showToast("Đã dán ảnh lên trang A4", "success");
  };
  img.src = dataUrl;
}

document.addEventListener("paste", (e) => {
  if (!state.pracSession.active || !wbState.ready) return;
  const activeTag = document.activeElement?.tagName;
  if (["INPUT", "TEXTAREA"].includes(activeTag) || document.activeElement?.isContentEditable) return;
  const items = e.clipboardData?.items || [];
  for (const it of items) {
    if (it.type.startsWith("image/")) {
      e.preventDefault();
      const file = it.getAsFile();
      if (file) compressImageFile(file, 1100, 0.88).then(drawImageOntoBoard);
      return;
    }
  }
});

function openWbTextEditorAt(clientX, clientY, canvasX, canvasY) {
  const stack = document.getElementById("wb-canvas-stack");
  const inp = document.getElementById("wb-floating-text-input");
  if (!stack || !inp) return;
  const rect = stack.getBoundingClientRect();
  wbState.pendingTextPos = { x: canvasX, y: canvasY };
  inp.style.display = "block";
  inp.style.left = `${Math.max(10, Math.min(rect.width - 210, clientX - rect.left))}px`;
  inp.style.top = `${Math.max(10, Math.min(rect.height - 50, clientY - rect.top))}px`;
  inp.style.color = wbState.color;
  inp.value = "";
  setTimeout(() => inp.focus(), 10);
}

function commitWbFloatingText() {
  const inp = document.getElementById("wb-floating-text-input");
  if (!inp || inp.style.display === "none") return;
  const txt = inp.value.trim();
  const pos = wbState.pendingTextPos;
  inp.style.display = "none";
  inp.value = "";
  wbState.pendingTextPos = null;
  if (!txt || !pos || !wbState.ready) return;
  const size = Number(document.getElementById("wb-size")?.value || 3.8);
  const fontPx = Math.round(20 + size * 3.5);
  wbState.strokes.push({ kind: "text", text: txt, x: pos.x, y: pos.y, fontPx, color: wbState.color });
  wbState.mainCtx.save();
  wbState.mainCtx.fillStyle = wbState.color;
  wbState.mainCtx.font = `700 ${fontPx}px 'Be Vietnam Pro', sans-serif`;
  wbState.mainCtx.fillText(txt, pos.x, pos.y + fontPx * 0.8);
  wbState.mainCtx.restore();
  wbSaveCurrentPageSnapshot();
}

function onWbTextKeydown(e) {
  if (e.key === "Enter") { e.preventDefault(); commitWbFloatingText(); }
  else if (e.key === "Escape") { const inp = document.getElementById("wb-floating-text-input"); if (inp) { inp.value = ""; inp.style.display = "none"; } wbState.pendingTextPos = null; }
}

function composePageForPublish(strokeDataUrl) {
  const c = document.createElement("canvas");
  c.width = wbState.mainCanvas.width;
  c.height = wbState.mainCanvas.height;
  const ctx = c.getContext("2d");
  drawA4PaperPattern(ctx, c.width, c.height, wbState.bgMode);
  return new Promise((resolve) => {
    if (!strokeDataUrl) return resolve(c.toDataURL("image/png"));
    const img = new Image();
    img.onload = () => { ctx.drawImage(img, 0, 0); resolve(c.toDataURL("image/png")); };
    img.src = strokeDataUrl;
  });
}

async function publishHandwrittenSolution() {
  const ps = state.pracSession;
  if (!ps.set || !wbState.ready) return;
  wbSaveCurrentPageSnapshot();
  const composedPages = [];
  for (const pObj of wbState.pages) {
    composedPages.push(await composePageForPublish(pObj?.dataUrl || ""));
  }
  const payload = {
    setId: ps.set.id,
    teacherName: state.user?.name || "Giáo viên",
    pages: composedPages,
    updatedAt: Date.now()
  };
  state.handwrittenSolutions[ps.set.id] = payload;
  saveAndBroadcast("hw_solution");
  if (isFirebaseLive) {
    fbDb.collection("handwrittenSolutions").doc(ps.set.id).set(payload).catch(() => {});
  }
  renderHandwrittenSolutionView(ps.set.id);
  renderManageSetsTable();
  showToast("Đã đẩy bài chữa A4 lên", "success");
}

function renderHandwrittenSolutionView(setId) {
  const box = document.getElementById("prac-handwritten-view");
  if (!box) return;
  const hw = state.handwrittenSolutions[setId];
  const isStaff = state.user && (state.user.role === "teacher" || state.user.role === "admin");

  if (!hw || !hw.pages || !hw.pages.length) {
    box.style.display = "none";
    return;
  }
  if (!isStaff && !state.pracSession.submitted) {
    box.style.display = "none";
    return;
  }

  const qs = state.pracSession.questions || [];
  const answerSummaryHtml = qs.length ? `
    <div style="margin:10px 0 14px;padding:10px 12px;border-radius:10px;background:var(--bg-base);border:1px solid var(--border);font-size:13px;">
      <strong>Đáp án chuẩn của đề:</strong>
      <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:6px;">
        ${qs.map((q, i) => {
          let ansText = "";
          if (q.part === 1) ansText = "ABCD"[q.answer] || "A";
          else if (q.part === 2) ansText = (q.statements || []).map((st, idx) => `${st.label}:${st.answer ? "Đ" : "S"}`).join(" ");
          else ansText = q.answer || "—";
          return `<span class="chip chip-primary">Câu ${i + 1}: <strong>${escapeHtml(ansText)}</strong></span>`;
        }).join("")}
      </div>
    </div>` : "";

  box.style.display = "block";
  box.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
      <strong><i class="fa-solid fa-pen-nib"></i> Đáp án & Chữa chi tiết A4 — ${escapeHtml(hw.teacherName || "Giáo viên")}</strong>
      <span class="muted">${new Date(hw.updatedAt).toLocaleString("vi-VN")}</span>
    </div>
    ${answerSummaryHtml}
    <div class="handwritten-gallery">
      ${hw.pages.map((src, idx) => `
        <div class="handwritten-page">
          <img src="${src}" alt="Trang A4 ${idx + 1}" onclick="openImageZoomModal(this.src)" />
        </div>`).join("")}
    </div>
  `;
}

// ---------------- ĐIỀU KHIỂN POPOVER SCRBLE INK ----------------
wbState.activePenType = "calligraphy";

function toggleScrblePopover(id, e) {
  if (e) e.stopPropagation();
  const target = document.getElementById(id);
  const wasOpen = target && target.classList.contains("open");
  document.querySelectorAll(".scrble-popover").forEach(p => p.classList.remove("open"));
  if (target && !wasOpen) target.classList.add("open");
}

document.addEventListener("click", (e) => {
  if (!e.target.closest(".scrble-popover-wrap")) {
    document.querySelectorAll(".scrble-popover").forEach(p => p.classList.remove("open"));
  }
});

function selectScrblePenType(penType, btn) {
  wbState.activePenType = penType;
  document.querySelectorAll(".scrble-type-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");

  const mainBtn = document.getElementById("scrble-pen-main-btn");
  if (mainBtn) {
    const iconCls = PEN_ICON_CLASS[penType] || "fa-solid fa-feather-pointed";
    mainBtn.innerHTML = `<i class="${iconCls}"></i>`;
    mainBtn.style.background = wbState.color || "#0f172a";
    mainBtn.style.color = (wbState.color || "").toLowerCase() === "#ffffff" ? "#0f172a" : "#ffffff";
  }

  setWbTool(penType, mainBtn);
}

function quickPickColor(hex) {
  setWbColor(hex, null);
}

function updateWbSizePreview(val) {
  const lbl = document.getElementById("wb-size-label");
  if (lbl) lbl.textContent = `${val}px`;
  const wave = document.getElementById("scrble-wave-path");
  if (wave) {
    wave.setAttribute("stroke-width", val);
    wave.setAttribute("stroke", wbState.color || "#0f172a");
  }
}

function pickShapeOrText(kind) {
  document.querySelectorAll(".scrble-popover").forEach(p => p.classList.remove("open"));
  if (kind === "text") {
    setWbTool("text", document.getElementById("scrble-shapes-btn"));
  } else {
    setWbShapeTool(kind);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  applyPreferences();
  renderUserUI();
  refreshAllViews();
  initWordDropzone();
  initFirebase();
  setInterval(() => {
    updateHolidayClock();
    if (state.prefs.holidayAuto && state.prefs.holidayPreview === "auto") {
      const detected = detectRealtimeHoliday();
      if ((detected?.id || null) !== (state.activeHoliday?.id || null)) applyRealtimeHoliday();
    }
  }, 30000);
});
