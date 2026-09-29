// dream-net's hero: a server and its peers, drawn from what dream-net actually does, rendered live
// with three.js.
//
// The drum is the `Server`: sixteen client slots, `max_clients` in the README's server, each a
// socket with a lamp and notches for its slot's generation, so a `PeerId` like "peer 3:2" is the
// third occupant of slot 3. The drum's face is engraved with the slot numbers, wire version 2 and
// the README's protocol id, 0x4452_4541_4D00_0001. In its hole floats the server's key, which never
// leaves `Server`, caged, and around it the schema's 128-bit fingerprint as sixteen bars, one per
// byte. The bezel turns through `Seq16` sequence numbers and wraps from 65535 to 0 a little after
// the page loads. Four lamps on the drum's front chase through the frame every host runs: update,
// poll, send, flush.
//
// Each peer hangs on two lanes: reliable-ordered, solid, and unreliable-unordered, dotted. Packets
// cross them: capsules for reliable events, beads for unreliable state, mint sparks for acks. A
// lost packet bursts; a lost reliable one is sent again, amber, and an unreliable one is simply
// gone. Beneath each peer is its acknowledgement field: the latest packet and the 32 before it.
// Peers come and go. A new one arrives saying hello with its fingerprint in a ring until the
// fingerprints are compared; one in five brings a different schema, and lingers red for
// `mismatch_linger`, a second, before it is rejected. A click sends the nearest peer a burst of
// sixteen reliable events, and it acknowledges at once, as a connection does after every sixteen.
// The pointer is the simulator: packets that cross its ring are delayed, duplicated or lost.
//
// One more socket sits on the drum's rim, facing the edge of the page, listening. It sends a hello
// out into nothing now and then.
//
// The scene renders to a half-float target; a bright pass and four blur passes make the bloom, and
// the composite applies ACES tone mapping and dithering after zeroing any NaN or infinity. Colours
// come from the site's CSS tokens. The art stands beside the hero's text, measured at every layout,
// or above it on a phone, where sass/brand.sass leaves room. Nothing runs while the hero is off
// screen or the tab is hidden, and the resolution drops if frames run slow. Under
// prefers-reduced-motion one frame is drawn. Until the first frame, and without WebGL, a still of
// the scene stands in its place.

import * as THREE from './vendor/three.module.min.js';

const TAU = Math.PI * 2;
const SLOTS = 16;
// The listening socket's side of the drum: simulated peers keep clear of it.
const RESERVED = new Set([15, 0, 1]);
const WIRE_VERSION = 2;
const ACK_BITS = 33;
const BURST = 16;
const HANDSHAKE_TIME = 1.4;
const MISMATCH_LINGER = 1.0;
// Event ids come from sorted canonical names, so the schema is written in that order.
const SCHEMA = 'dream-net hero schema 1\nchannel reliable reliable-ordered\nchannel state unreliable-unordered\nevent ActorPosition state 28\nevent Chat reliable 256\n';
const BUS_NAME = 'dream-net-hero';
const BUS_IDLE = 1.0;
const REMOTE_LIMIT = 3;
const SEQ_START = 65470;

// The composition in the drum's units: the drum has radius 0.62, peers stand out to 1.35 and the
// peers across the listening socket to 1.62 on the right. MARK is its box once tilted.
const DRUM = { outer: 0.62, inner: 0.34, depth: 0.1, socket: 0.5, numbers: 0.425 };
const TOP = DRUM.depth / 2 + 0.018;
const MARK = { width: 3.25, height: 2.1, x: 0.16, y: 0.1 };
const MARK_ASPECT = MARK.width / MARK.height;
const TILT = 0.62;
const SAMPLES = 26;
const MAX_LINKS = SLOTS + REMOTE_LIMIT + 1;
const LISTEN_LINK = MAX_LINKS - 1;
const MAX_PACKETS = 360;
const MAX_SPARKS = 420;

const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

function cssColor(name, fallback) {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const color = new THREE.Color(fallback);
  if (raw) {
    try { color.setStyle(raw); } catch { /* an unparsable token keeps the fallback */ }
  }
  return color;
}

function random(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const clamp01 = (value) => Math.min(1, Math.max(0, value));
// Other tabs keep wall-clock time: their handshakes and departures finish even while this tab's
// frames are slow or paused.
const wall = () => performance.now() / 1000;
const ease = (value) => {
  const t = clamp01(value);
  return t * t * (3 - 2 * t);
};
// Seq16: a is newer than b across the wrap, as dream-net compares sequence numbers.
const seqNewer = (a, b) => (a > b && a - b <= 32768) || (a < b && b - a > 32768);

// The schema's fingerprint, as dream-net takes it: SHA-256, truncated to 128 bits. Without subtle
// crypto, outside a secure context, a keyed FNV stands in; both tabs compute the same one.
async function fingerprint(text) {
  const bytes = new TextEncoder().encode(text);
  try {
    if (globalThis.crypto && crypto.subtle) {
      return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)).slice(0, 16));
    }
  } catch { /* an insecure context has no subtle crypto */ }
  const out = [];
  for (let lane = 0; lane < 4; lane++) {
    let hash = (0x811c9dc5 ^ Math.imul(lane + 1, 0x9e3779b9)) >>> 0;
    for (const byte of bytes) hash = Math.imul(hash ^ byte, 0x01000193) >>> 0;
    out.push(hash >>> 24, (hash >>> 16) & 255, (hash >>> 8) & 255, hash & 255);
  }
  return out;
}

const toHex = (bytes) => bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('');

// Between tabs of this site: a BroadcastChannel, or storage events where there is none.
function openBus(onMessage) {
  try {
    if (typeof BroadcastChannel === 'function') {
      const channel = new BroadcastChannel(BUS_NAME);
      channel.onmessage = (event) => onMessage(event.data);
      return {
        send(message) { try { channel.postMessage(message); } catch { /* a closed channel drops it */ } },
        close() { try { channel.close(); } catch { /* already closed */ } },
      };
    }
  } catch { /* fall through to storage events */ }
  const key = `${BUS_NAME}:bus`;
  const listener = (event) => {
    if (event.key !== key || !event.newValue) return;
    try { onMessage(JSON.parse(event.newValue).message); } catch { /* not ours */ }
  };
  try { addEventListener('storage', listener); } catch { /* no storage events */ }
  let nonce = 0;
  return {
    send(message) {
      try { localStorage.setItem(key, JSON.stringify({ message, nonce: `${Date.now()}-${nonce++}-${Math.random()}` })); } catch { /* storage refused */ }
    },
    close() {
      try { removeEventListener('storage', listener); } catch { /* nothing to remove */ }
    },
  };
}

// Texture baking ---------------------------------------------------------------------------------

// Local drum-top coordinates (x, z) on the cap's planar UVs, in canvas pixels. The cap's UVs are
// the shape's own coordinates, and the shape's y is the drum's -z.
function capPixel(x, z, size) {
  return [(x / (2 * DRUM.outer) + 0.5) * size, (z / (2 * DRUM.outer) + 0.5) * size];
}

// The drum's face: lathe grooves, and engraving filled with enamel that faintly glows.
function drumMaps(size, anisotropy, monoFont) {
  const engrave = document.createElement('canvas');
  engrave.width = engrave.height = size;
  const g = engrave.getContext('2d');
  g.fillStyle = '#000';
  g.fillRect(0, 0, size, size);
  g.fillStyle = '#fff';
  g.textAlign = 'center';
  g.textBaseline = 'middle';
  const pixelsPerUnit = size / (2 * DRUM.outer);
  // Slot numbers, read from outside the drum.
  g.font = `700 ${Math.round(0.052 * pixelsPerUnit)}px ${monoFont}`;
  for (let slot = 0; slot < SLOTS; slot++) {
    const angle = slot / SLOTS * TAU;
    const [px, py] = capPixel(Math.cos(angle) * DRUM.numbers, Math.sin(angle) * DRUM.numbers, size);
    g.save();
    g.translate(px, py);
    g.rotate(angle + Math.PI / 2);
    g.fillText(String(slot).padStart(2, '0'), 0, 0);
    g.restore();
  }
  // Round the inner rim: what the README's server says about itself.
  const legend = ' PROTOCOL 0x4452 4541 4D00 0001 · WIRE v2 · MAX CLIENTS 16 · NETCODE · RELIABLE · SERIALIZE ·';
  g.font = `600 ${Math.round(0.026 * pixelsPerUnit)}px ${monoFont}`;
  const radius = DRUM.inner + 0.035;
  const step = TAU / legend.length;
  for (let i = 0; i < legend.length; i++) {
    const angle = -Math.PI / 2 + i * step;
    const [px, py] = capPixel(Math.cos(angle) * radius, Math.sin(angle) * radius, size);
    g.save();
    g.translate(px, py);
    g.rotate(angle + Math.PI / 2);
    g.fillText(legend[i], 0, 0);
    g.restore();
  }
  // Slot pads: a shallow recess under every socket.
  for (let slot = 0; slot < SLOTS; slot++) {
    const angle = slot / SLOTS * TAU;
    const [px, py] = capPixel(Math.cos(angle) * DRUM.socket, Math.sin(angle) * DRUM.socket, size);
    g.save();
    g.translate(px, py);
    g.rotate(angle + Math.PI / 2);
    g.globalAlpha = 0.22;
    g.fillRect(-0.05 * pixelsPerUnit, -0.036 * pixelsPerUnit, 0.1 * pixelsPerUnit, 0.072 * pixelsPerUnit);
    g.restore();
  }
  g.globalAlpha = 1;
  const marks = g.getImageData(0, 0, size, size).data;

  const height = new Float32Array(size * size);
  const colour = new Uint8ClampedArray(size * size * 4);
  const surface = new Uint8ClampedArray(size * size * 4);
  const glow = new Uint8ClampedArray(size * size * 4);
  const noise = random(0x44524541);
  const grain = new Float32Array(4096);
  for (let i = 0; i < grain.length; i++) grain[i] = noise();
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = y * size + x;
      const u = (x + 0.5) / size - 0.5;
      const v = (y + 0.5) / size - 0.5;
      const r = Math.hypot(u, v) * 2 * DRUM.outer;
      const mark = marks[i * 4] / 255;
      // Lathe grooves, finer towards the rim, with bands where the tool was stepped.
      const groove = Math.sin(r * 820) * 0.5 + 0.5;
      const band = Math.sin(r * 31 + 1.3) * 0.5 + 0.5;
      const speck = grain[(x * 7 + y * 131) & 4095];
      height[i] = groove * 0.35 + band * 0.1 - mark * 1.4 + speck * 0.04;
      const shade = 0.72 + band * 0.18 + groove * 0.06 + speck * 0.05 - mark * 0.35;
      colour[i * 4] = 255 * shade * 0.78;
      colour[i * 4 + 1] = 255 * shade * 0.84;
      colour[i * 4 + 2] = 255 * shade * 0.94;
      colour[i * 4 + 3] = 255;
      const rough = 0.22 + (1 - groove) * 0.1 + band * 0.08 + mark * 0.4;
      surface[i * 4] = 255;
      surface[i * 4 + 1] = 255 * clamp01(rough);
      surface[i * 4 + 2] = 255 * (1 - mark * 0.7);
      surface[i * 4 + 3] = 255;
      glow[i * 4] = glow[i * 4 + 1] = glow[i * 4 + 2] = 255 * mark;
      glow[i * 4 + 3] = 255;
    }
  }
  const normal = new Uint8ClampedArray(size * size * 4);
  const strength = size / 512 * 1.6;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const left = height[y * size + Math.max(0, x - 1)];
      const right = height[y * size + Math.min(size - 1, x + 1)];
      const up = height[Math.max(0, y - 1) * size + x];
      const down = height[Math.min(size - 1, y + 1) * size + x];
      const nx = (left - right) * strength;
      const ny = (down - up) * strength;
      const length = Math.hypot(nx, ny, 1);
      const i = (y * size + x) * 4;
      normal[i] = (nx / length * 0.5 + 0.5) * 255;
      normal[i + 1] = (ny / length * 0.5 + 0.5) * 255;
      normal[i + 2] = (1 / length * 0.5 + 0.5) * 255;
      normal[i + 3] = 255;
    }
  }
  const texture = (data, colorSpace) => {
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = size;
    canvas.getContext('2d').putImageData(new ImageData(data, size, size), 0, 0);
    const map = new THREE.CanvasTexture(canvas);
    map.colorSpace = colorSpace;
    map.anisotropy = anisotropy;
    map.repeat.set(1, 1);
    map.wrapS = map.wrapT = THREE.ClampToEdgeWrapping;
    return map;
  };
  return {
    map: texture(colour, THREE.SRGBColorSpace),
    normal: texture(normal, THREE.NoColorSpace),
    surface: texture(surface, THREE.NoColorSpace),
    glow: texture(glow, THREE.SRGBColorSpace),
  };
}

// A peer's name plate, like dream-net prints it.
function plate(monoFont) {
  const canvas = document.createElement('canvas');
  canvas.width = 320;
  canvas.height = 64;
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  let last = '';
  return {
    texture,
    draw(text, stroke, fill) {
      const key = `${text}|${stroke}|${fill}`;
      if (key === last) return;
      last = key;
      const g = canvas.getContext('2d');
      g.clearRect(0, 0, canvas.width, canvas.height);
      g.font = `600 26px ${monoFont}`;
      const width = Math.min(canvas.width - 4, g.measureText(text).width + 28);
      const x = (canvas.width - width) / 2;
      g.fillStyle = 'rgba(6, 11, 18, 0.78)';
      g.strokeStyle = stroke;
      g.lineWidth = 2;
      g.beginPath();
      if (g.roundRect) g.roundRect(x, 10, width, 44, 10);
      else g.rect(x, 10, width, 44);
      g.fill();
      g.stroke();
      g.fillStyle = fill;
      g.textAlign = 'center';
      g.textBaseline = 'middle';
      g.fillText(text, canvas.width / 2, 33);
      texture.needsUpdate = true;
    },
  };
}

function environment(renderer, accent) {
  const scene = new THREE.Scene();
  const disposables = [];
  const add = (geometry, color, position) => {
    const material = new THREE.MeshBasicMaterial({ color, side: THREE.DoubleSide });
    const mesh = new THREE.Mesh(geometry, material);
    mesh.position.set(...position);
    mesh.lookAt(0, 0, 0);
    scene.add(mesh);
    disposables.push(geometry, material);
  };
  const room = new THREE.Mesh(new THREE.BoxGeometry(26, 16, 26), new THREE.MeshBasicMaterial({ color: new THREE.Color(0.025, 0.035, 0.05), side: THREE.BackSide }));
  scene.add(room);
  disposables.push(room.geometry, room.material);
  add(new THREE.PlaneGeometry(14, 6), new THREE.Color(0.85, 0.92, 1.0).multiplyScalar(3.2), [-6, 7, 6]);
  add(new THREE.PlaneGeometry(9, 5), new THREE.Color(0.9, 0.95, 1.0).multiplyScalar(1.6), [8, 4, 7]);
  add(new THREE.PlaneGeometry(14, 0.5), accent.clone().multiplyScalar(6), [7, 2.2, -8]);
  add(new THREE.PlaneGeometry(14, 0.4), accent.clone().multiplyScalar(4), [-8, 0.5, -7]);
  add(new THREE.PlaneGeometry(20, 0.3), new THREE.Color(0.55, 0.8, 1.0).multiplyScalar(3), [0, -0.8, -12]);
  add(new THREE.PlaneGeometry(24, 24), new THREE.Color(0.08, 0.12, 0.18).multiplyScalar(0.6), [0, -7.5, 0]);
  const generator = new THREE.PMREMGenerator(renderer);
  const target = generator.fromScene(scene, 0.03);
  generator.dispose();
  for (const item of disposables) item.dispose();
  return target;
}

// Shaders ----------------------------------------------------------------------------------------

const FULLSCREEN_VERTEX = /* glsl */ `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = vec4(position.xy, 0.0, 1.0);
  }
`;

// The page's own background, a cool glow behind the drum, and the wire: rows of packed bits, ones
// as bars and zeroes as rings, in datagram-long runs, sliding towards the drum.
const SKY_FRAGMENT = /* glsl */ `
  uniform vec3 uTop;
  uniform vec3 uBottom;
  uniform vec3 uAccent;
  uniform vec2 uCenter;
  uniform vec2 uResolution;
  uniform float uRadius;
  uniform float uTime;
  uniform float uBits;
  uniform vec4 uClip;
  uniform vec2 uHalf;
  varying vec2 vUv;
  float hash1(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
  void main() {
    vec3 color = mix(uBottom, uTop, vUv.y);
    float aspect = uResolution.x / max(uResolution.y, 1.0);
    vec2 d = (vUv - uCenter) * vec2(aspect, 1.0);
    float r = length(d);
    float radius = max(uRadius, 1e-3);
    color += uAccent * exp(-r * r / (radius * radius)) * 0.075;

    // Cells of 17 CSS pixels, whatever the hero's size.
    vec2 p = vUv * uResolution / 17.0;
    float row = floor(p.y);
    float speed = 0.45 + hash1(vec2(row, 3.1)) * 1.1;
    float x = p.x - uTime * speed;
    float cell = floor(x);
    vec2 f = vec2(fract(x), fract(p.y)) - 0.5;
    float bit = step(0.5, hash1(vec2(cell, row)));
    float runLength = 6.0 + floor(hash1(vec2(row, 7.7)) * 12.0);
    float inRun = step(mod(cell, runLength + 4.0), runLength - 0.5);
    float one = (1.0 - smoothstep(0.05, 0.1, abs(f.x))) * (1.0 - smoothstep(0.24, 0.3, abs(f.y)));
    float zero = 1.0 - smoothstep(0.04, 0.09, abs(length(f * vec2(1.3, 1.0)) - 0.19));
    float glyph = mix(zero, one, bit) * inRun * step(0.5, hash1(vec2(row, 1.9)));
    float near = 1.0 - smoothstep(0.8, 1.3, length((vUv - uCenter) / max(uHalf, vec2(1e-3))));
    // Only on the art's side of the hero: never behind the words.
    float clip = smoothstep(uClip.x, uClip.x + 0.05, vUv.x) * smoothstep(uClip.y, uClip.y + 0.05, vUv.y);
    color += uAccent * glyph * near * clip * uBits;
    gl_FragColor = vec4(color, 1.0);
  }
`;

// Link lanes: a bright core and a soft halo across the ribbon; the unreliable lane is dotted, and
// its dots run towards the peer.
const LINK_VERTEX = /* glsl */ `
  attribute vec3 aColor;
  attribute float aLane;
  varying vec2 vUv;
  varying vec3 vColor;
  varying float vLane;
  void main() {
    vUv = uv;
    vColor = aColor;
    vLane = aLane;
    gl_Position = projectionMatrix * viewMatrix * vec4(position, 1.0);
  }
`;

const LINK_FRAGMENT = /* glsl */ `
  uniform float uTime;
  varying vec2 vUv;
  varying vec3 vColor;
  varying float vLane;
  void main() {
    float across = abs(vUv.y * 2.0 - 1.0);
    float core = 1.0 - smoothstep(0.0, 0.3, across);
    float halo = 1.0 - smoothstep(0.15, 1.0, across);
    float dash = step(0.42, fract(vUv.x * 44.0 - uTime * 1.3));
    float dots = mix(1.0, dash, vLane);
    gl_FragColor = vec4(vColor * (core + halo * 0.3) * dots, 1.0);
  }
`;

// The simulator's ring, where the pointer is: interference on the wire.
const LENS_VERTEX = /* glsl */ `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const LENS_FRAGMENT = /* glsl */ `
  uniform float uTime;
  uniform vec3 uColor;
  uniform float uStrength;
  varying vec2 vUv;
  void main() {
    vec2 p = vUv * 2.0 - 1.0;
    float r = length(p);
    float angle = r > 1e-4 ? atan(p.y, p.x) : 0.0;
    float rim = 1.0 - smoothstep(0.008, 0.03, abs(r - 0.92));
    float inner = 1.0 - smoothstep(0.006, 0.022, abs(r - 0.72));
    float turn = fract(angle / 6.2831853 * 24.0 - uTime * 0.25);
    float ticks = step(0.62, turn) * (1.0 - smoothstep(0.02, 0.045, abs(r - 0.82)));
    float gap = step(0.18, fract(angle / 6.2831853 * 3.0 + uTime * 0.12));
    float shimmer = (1.0 - smoothstep(0.3, 0.72, r)) * (0.5 + 0.5 * sin(r * 40.0 - uTime * 2.4 + angle * 3.0)) * 0.07;
    gl_FragColor = vec4(uColor * (rim * gap + inner * 0.45 + ticks * 0.55 + shimmer) * uStrength, 1.0);
  }
`;

const SPARK_VERTEX = /* glsl */ `
  attribute float aLife;
  attribute vec3 aColor;
  uniform float uPixel;
  varying float vLife;
  varying vec3 vColor;
  void main() {
    vec4 view = modelViewMatrix * vec4(position, 1.0);
    gl_Position = projectionMatrix * view;
    gl_PointSize = clamp(uPixel / max(-view.z, 0.1) * (0.35 + aLife * 0.65), 1.0, 28.0);
    vLife = aLife;
    vColor = aColor;
  }
`;

const SPARK_FRAGMENT = /* glsl */ `
  varying float vLife;
  varying vec3 vColor;
  void main() {
    vec2 p = gl_PointCoord * 2.0 - 1.0;
    float d = dot(p, p);
    float alpha = (1.0 - smoothstep(0.1, 1.0, d)) * vLife;
    gl_FragColor = vec4(vColor * alpha, 1.0);
  }
`;

// Any NaN or infinity a driver produces is zeroed and bright values capped before the bloom, which
// would otherwise smear a single bad pixel into a black square.
const SCRUB = /* glsl */ `
  vec3 scrub(vec3 c) {
    if (any(isnan(c)) || any(isinf(c)) || c.r != c.r || c.g != c.g || c.b != c.b) return vec3(0.0);
    return clamp(c, 0.0, 64.0);
  }
`;

const BRIGHT_FRAGMENT = /* glsl */ `
  uniform sampler2D tInput;
  uniform float uThreshold;
  varying vec2 vUv;
  ${SCRUB}
  void main() {
    vec3 c = scrub(texture2D(tInput, vUv).rgb);
    float luma = dot(c, vec3(0.2126, 0.7152, 0.0722));
    gl_FragColor = vec4(c * smoothstep(uThreshold, uThreshold + 0.8, luma), 1.0);
  }
`;

const BLUR_FRAGMENT = /* glsl */ `
  uniform sampler2D tInput;
  uniform vec2 uDirection;
  varying vec2 vUv;
  void main() {
    vec3 sum = texture2D(tInput, vUv).rgb * 0.2270270270;
    sum += texture2D(tInput, vUv + uDirection * 1.3846153846).rgb * 0.3162162162;
    sum += texture2D(tInput, vUv - uDirection * 1.3846153846).rgb * 0.3162162162;
    sum += texture2D(tInput, vUv + uDirection * 3.2307692308).rgb * 0.0702702703;
    sum += texture2D(tInput, vUv - uDirection * 3.2307692308).rgb * 0.0702702703;
    gl_FragColor = vec4(sum, 1.0);
  }
`;

const COMPOSITE_FRAGMENT = /* glsl */ `
  uniform sampler2D tScene;
  uniform sampler2D tBloomNear;
  uniform sampler2D tBloomFar;
  uniform float uTime;
  varying vec2 vUv;
  vec3 aces(vec3 x) {
    return clamp((x * (2.51 * x + 0.03)) / (x * (2.43 * x + 0.59) + 0.14), 0.0, 1.0);
  }
  float dither(vec2 p) {
    return fract(sin(dot(p + fract(uTime), vec2(12.9898, 78.233))) * 43758.5453) - 0.5;
  }
  ${SCRUB}
  void main() {
    vec3 color = scrub(texture2D(tScene, vUv).rgb);
    color += scrub(texture2D(tBloomNear, vUv).rgb) * 0.75 + scrub(texture2D(tBloomFar, vUv).rgb) * 0.6;
    color = aces(color * 0.95);
    color = pow(color, vec3(1.0 / 2.2));
    color += dither(gl_FragCoord.xy) / 255.0;
    gl_FragColor = vec4(color, 1.0);
  }
`;

function fullscreenMaterial(fragmentShader, uniforms) {
  return new THREE.ShaderMaterial({ vertexShader: FULLSCREEN_VERTEX, fragmentShader, uniforms, depthTest: false, depthWrite: false });
}

// Layout -------------------------------------------------------------------------------------------

// Where the hero's words and controls are, so the art can stand clear of them.
function textRects(text) {
  const rects = [];
  const range = document.createRange();
  const walker = document.createTreeWalker(text, NodeFilter.SHOW_TEXT, {
    acceptNode: (node) => (node.nodeValue.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT),
  });
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    range.selectNodeContents(node);
    for (const rect of range.getClientRects()) rects.push(rect);
  }
  for (const element of text.querySelectorAll('a, button, input, select, img, svg, .dw-command, .dw-badge')) rects.push(element.getBoundingClientRect());
  return rects.filter((rect) => rect.width > 0 && rect.height > 0);
}

// The largest box of the art's shape clear of the text: beside all of it, beside the title rows
// above the summary, or above it all where the stylesheet has left room on a phone. Returns its
// centre relative to the art, and its height.
function placement(root) {
  const hero = root.closest('.dw-hero') || root.parentElement;
  const box = root.getBoundingClientRect();
  const text = hero.querySelector('.dw-hero__text') || hero.querySelector('.dw-shell');
  const strip = hero.querySelector('.dw-strip');
  const shellElement = hero.querySelector('.dw-hero__grid') || hero.querySelector('.dw-shell') || hero;
  const shellStyle = getComputedStyle(shellElement);
  const shellBox = shellElement.getBoundingClientRect();
  const shell = strip ? strip.getBoundingClientRect() : { left: shellBox.left + parseFloat(shellStyle.paddingLeft), right: shellBox.right - parseFloat(shellStyle.paddingRight) };
  const summary = hero.querySelector('.dw-hero__summary');
  const floor = strip ? strip.getBoundingClientRect().top : box.bottom - 24;
  const rects = text ? textRects(text) : [];
  if (!rects.length) return { x: box.width * 0.72, y: box.height * 0.45, size: Math.min(box.width * 0.3 / MARK_ASPECT, box.height * 0.7), above: false };
  const gap = 28;
  const right = Math.max(...rects.map((rect) => rect.right));
  const top = Math.min(...rects.map((rect) => rect.top));
  const summaryTop = summary ? summary.getBoundingClientRect().top : floor;
  const headRects = rects.filter((rect) => rect.bottom <= summaryTop + 1);
  const headRight = headRects.length ? Math.max(...headRects.map((rect) => rect.right)) : right;
  const candidates = [
    { x0: right + gap, x1: shell.right + 12, y0: box.top + 34, y1: floor - 8, above: false },
    { x0: headRight + gap, x1: shell.right + 12, y0: box.top + 30, y1: summaryTop - 10, above: false },
    { x0: shell.left - 8, x1: shell.right + 8, y0: box.top + 8, y1: top - 10, above: true },
  ].map((region) => {
    const width = region.x1 - region.x0;
    const height = region.y1 - region.y0;
    return { ...region, size: Math.max(0, Math.min(height, width / MARK_ASPECT)) };
  });
  const best = candidates.reduce((a, b) => (b.size > a.size ? b : a));
  const size = Math.min(best.size * 0.96, 470);
  const markWidth = size * MARK_ASPECT;
  const x = best.above ? (best.x0 + best.x1) / 2 : Math.min(best.x1 - markWidth / 2, (best.x0 + best.x1) / 2 + (best.x1 - best.x0 - markWidth) * 0.3);
  return { x: x - box.left, y: (best.y0 + best.y1) / 2 - box.top, size, above: best.above };
}

// The scene --------------------------------------------------------------------------------------

function mount(root) {
  const still = document.createElement('img');
  still.className = 'dn-hero__still';
  still.alt = '';
  still.decoding = 'async';
  still.src = new URL('../img/dream-net-hero.webp', import.meta.url).href;
  root.append(still);

  // The still was cut from the live scene with a margin of 4% on every side.
  function placeStill() {
    const spot = placement(root);
    const height = spot.size * 1.08;
    const width = spot.size * MARK_ASPECT * 1.08;
    Object.assign(still.style, {
      left: `${spot.x - width / 2}px`,
      top: `${spot.y - height / 2}px`,
      width: `${width}px`,
      height: `${height}px`,
    });
    root.classList.add('is-placed');
  }

  const canvas = document.createElement('canvas');
  canvas.className = 'dn-hero__canvas';
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: false, alpha: false, powerPreference: 'high-performance' });
  } catch {
    placeStill();
    return;
  }
  if (!renderer.capabilities.isWebGL2) {
    renderer.dispose();
    placeStill();
    return;
  }
  renderer.autoClear = false;
  renderer.outputColorSpace = THREE.LinearSRGBColorSpace;
  root.append(canvas);

  const small = Math.min(innerWidth, innerHeight) < 700;
  const floatTargets = renderer.extensions.has('EXT_color_buffer_float') || renderer.extensions.has('EXT_color_buffer_half_float');
  const targetType = floatTargets ? THREE.HalfFloatType : THREE.UnsignedByteType;
  const makeTarget = () => new THREE.WebGLRenderTarget(1, 1, { type: targetType, depthBuffer: false });
  const sceneTarget = new THREE.WebGLRenderTarget(1, 1, { type: targetType, samples: small ? 2 : 4 });
  const bloomTargets = [makeTarget(), makeTarget(), makeTarget(), makeTarget()];
  const anisotropy = Math.min(8, renderer.capabilities.getMaxAnisotropy());

  const accent = cssColor('--dw-accent', '#74bdff');
  const okColor = cssColor('--dw-ok', '#8fdcb0');
  const warnColor = cssColor('--dw-warn', '#ecd18f');
  const dangerColor = cssColor('--dw-danger', '#ffaea2');
  const infoColor = cssColor('--dw-info', '#9cc7ff');
  const top = cssColor('--dw-bg-1', '#0d141b');
  const bottom = cssColor('--dw-bg-0', '#070c11');
  const monoFont = getComputedStyle(document.documentElement).getPropertyValue('--dw-font-mono').trim() || 'ui-monospace, monospace';
  const srgb = { r: 0, g: 0, b: 0 };
  const css = (source, alpha = 1) => {
    source.getRGB(srgb, THREE.SRGBColorSpace);
    return `rgba(${Math.round(srgb.r * 255)}, ${Math.round(srgb.g * 255)}, ${Math.round(srgb.b * 255)}, ${alpha})`;
  };
  // Colours for things, in linear light; the accent is sRGB from CSS, which three stores linear.
  const hot = (color, gain) => color.clone().multiplyScalar(gain);

  const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 80);
  camera.position.set(0, 0.8, 10);
  camera.lookAt(0, 0, 0);

  const scene = new THREE.Scene();
  const envTarget = environment(renderer, accent);
  scene.environment = envTarget.texture;

  const quad = new THREE.PlaneGeometry(2, 2);
  const skyUniforms = {
    uTop: { value: top },
    uBottom: { value: bottom },
    uAccent: { value: accent },
    uCenter: { value: new THREE.Vector2(0.75, 0.5) },
    uResolution: { value: new THREE.Vector2(1, 1) },
    uRadius: { value: 0.3 },
    uTime: { value: 0 },
    uBits: { value: 0.085 },
    uClip: { value: new THREE.Vector4(0, 0, 1, 1) },
    uHalf: { value: new THREE.Vector2(0.2, 0.3) },
  };
  const sky = new THREE.Mesh(quad, fullscreenMaterial(SKY_FRAGMENT, skyUniforms));
  sky.frustumCulled = false;
  sky.renderOrder = -10;
  scene.add(sky);

  // The rig: everything that belongs to the server, in the drum's units, tilted towards the viewer.
  const rig = new THREE.Group();
  rig.rotation.order = 'YXZ';
  scene.add(rig);

  // The drum.
  const maps = drumMaps(small ? 512 : 1024, anisotropy, monoFont);
  const shape = new THREE.Shape().absarc(0, 0, DRUM.outer, 0, TAU, false);
  shape.holes.push(new THREE.Path().absarc(0, 0, DRUM.inner, 0, TAU, true));
  const drumGeometry = new THREE.ExtrudeGeometry(shape, {
    depth: DRUM.depth, bevelEnabled: true, bevelThickness: 0.018, bevelSize: 0.014, bevelSegments: 4, curveSegments: small ? 96 : 160,
  });
  drumGeometry.rotateX(-Math.PI / 2);
  drumGeometry.translate(0, -DRUM.depth / 2, 0);
  // The cap's planar UVs are the shape's coordinates; map them onto the baked face.
  const uv = drumGeometry.attributes.uv;
  for (let i = 0; i < uv.count; i++) uv.setXY(i, uv.getX(i) / (2 * DRUM.outer) + 0.5, uv.getY(i) / (2 * DRUM.outer) + 0.5);
  const drum = new THREE.Mesh(drumGeometry, new THREE.MeshPhysicalMaterial({
    map: maps.map,
    normalMap: maps.normal,
    normalScale: new THREE.Vector2(0.55, 0.55),
    roughnessMap: maps.surface,
    roughness: 1,
    metalnessMap: maps.surface,
    metalness: 1,
    color: new THREE.Color(0.62, 0.68, 0.78),
    emissiveMap: maps.glow,
    emissive: accent.clone().multiplyScalar(0.55),
    emissiveIntensity: 1,
    clearcoat: 0.35,
    clearcoatRoughness: 0.25,
    envMapIntensity: 1.15,
  }));
  rig.add(drum);

  // The bezel: Seq16's dial, 64 ticks, one lit for the current sequence number.
  const bezelMaterial = new THREE.MeshPhysicalMaterial({ color: new THREE.Color(0.55, 0.6, 0.68), metalness: 1, roughness: 0.22, clearcoat: 0.6, envMapIntensity: 1.3, emissive: accent.clone(), emissiveIntensity: 0 });
  const bezel = new THREE.Mesh(new THREE.TorusGeometry(DRUM.outer + 0.07, 0.009, 10, small ? 128 : 220), bezelMaterial);
  bezel.rotation.x = Math.PI / 2;
  rig.add(bezel);
  const tickCount = 64;
  const ticks = new THREE.InstancedMesh(new THREE.BoxGeometry(0.006, 0.006, 0.03), new THREE.MeshBasicMaterial({ color: 0xffffff }), tickCount);
  ticks.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
  const dial = new THREE.Group();
  dial.add(ticks);
  rig.add(dial);
  const matrix = new THREE.Matrix4();
  const quaternion = new THREE.Quaternion();
  const vector = new THREE.Vector3();
  const unit = new THREE.Vector3(1, 1, 1);
  const up = new THREE.Vector3(0, 1, 0);
  for (let i = 0; i < tickCount; i++) {
    const angle = i / tickCount * TAU;
    quaternion.setFromAxisAngle(up, Math.PI / 2 - angle);
    vector.set(Math.cos(angle) * (DRUM.outer + 0.07), 0.012, Math.sin(angle) * (DRUM.outer + 0.07));
    matrix.compose(vector, quaternion, unit);
    ticks.setMatrixAt(i, matrix);
    ticks.setColorAt(i, hot(infoColor, 0.35));
  }

  // Sockets, their lamps and their generation notches.
  const socketMesh = new THREE.InstancedMesh(new THREE.BoxGeometry(0.075, 0.03, 0.05), new THREE.MeshPhysicalMaterial({ color: new THREE.Color(0.04, 0.05, 0.07), metalness: 0.4, roughness: 0.45, clearcoat: 0.8, clearcoatRoughness: 0.15 }), SLOTS);
  const lampMesh = new THREE.InstancedMesh(new THREE.BoxGeometry(0.018, 0.008, 0.014), new THREE.MeshBasicMaterial({ color: 0xffffff }), SLOTS);
  const notchMesh = new THREE.InstancedMesh(new THREE.BoxGeometry(0.008, 0.006, 0.02), new THREE.MeshBasicMaterial({ color: 0xffffff }), SLOTS * 4);
  for (let slot = 0; slot < SLOTS; slot++) {
    const angle = slot / SLOTS * TAU;
    quaternion.setFromAxisAngle(up, -angle - Math.PI / 2);
    vector.set(Math.cos(angle) * DRUM.socket, TOP + 0.004, Math.sin(angle) * DRUM.socket);
    matrix.compose(vector, quaternion, unit);
    socketMesh.setMatrixAt(slot, matrix);
    vector.set(Math.cos(angle) * (DRUM.socket - 0.045), TOP + 0.003, Math.sin(angle) * (DRUM.socket - 0.045));
    matrix.compose(vector, quaternion, unit);
    lampMesh.setMatrixAt(slot, matrix);
    lampMesh.setColorAt(slot, new THREE.Color(0, 0, 0));
    for (let j = 0; j < 4; j++) {
      const notchAngle = angle + (j - 1.5) * 0.028;
      quaternion.setFromAxisAngle(up, Math.PI / 2 - notchAngle);
      vector.set(Math.cos(notchAngle) * (DRUM.outer - 0.03), TOP + 0.002, Math.sin(notchAngle) * (DRUM.outer - 0.03));
      matrix.compose(vector, quaternion, unit);
      notchMesh.setMatrixAt(slot * 4 + j, matrix);
      notchMesh.setColorAt(slot * 4 + j, new THREE.Color(0, 0, 0));
    }
  }
  rig.add(socketMesh, lampMesh, notchMesh);

  // The frame: four lamps on the drum's front, chasing through update, poll, send, flush.
  const frameMesh = new THREE.InstancedMesh(new THREE.BoxGeometry(0.05, 0.022, 0.006), new THREE.MeshBasicMaterial({ color: 0xffffff }), 4);
  for (let i = 0; i < 4; i++) {
    const angle = Math.PI / 2 + (i - 1.5) * 0.105;
    quaternion.setFromAxisAngle(up, -angle + Math.PI / 2);
    vector.set(Math.cos(angle) * (DRUM.outer + 0.016), 0, Math.sin(angle) * (DRUM.outer + 0.016));
    matrix.compose(vector, quaternion, unit);
    frameMesh.setMatrixAt(i, matrix);
    frameMesh.setColorAt(i, new THREE.Color(0, 0, 0));
  }
  rig.add(frameMesh);

  // The listening socket, on the rim, facing the edge of the page.
  const port = new THREE.Group();
  const portBody = new THREE.Mesh(new THREE.CylinderGeometry(0.036, 0.04, 0.05, 32, 1, true), new THREE.MeshPhysicalMaterial({ color: new THREE.Color(0.5, 0.56, 0.64), metalness: 1, roughness: 0.25, side: THREE.DoubleSide, envMapIntensity: 1.2 }));
  portBody.rotation.z = -Math.PI / 2;
  const portMouth = new THREE.Mesh(new THREE.CircleGeometry(0.03, 32), new THREE.MeshBasicMaterial({ color: new THREE.Color(0.01, 0.015, 0.02) }));
  portMouth.rotation.y = Math.PI / 2;
  portMouth.position.x = 0.012;
  const portRingMaterial = new THREE.MeshBasicMaterial({ color: hot(accent, 1) });
  const portRing = new THREE.Mesh(new THREE.TorusGeometry(0.043, 0.005, 8, 48), portRingMaterial);
  portRing.rotation.y = Math.PI / 2;
  portRing.position.x = 0.026;
  port.add(portBody, portMouth, portRing);
  port.position.set(DRUM.outer + 0.012, 0, 0);
  rig.add(port);

  // The key, caged, and the schema's fingerprint around it.
  const coreMaterial = new THREE.MeshPhysicalMaterial({
    color: new THREE.Color(0.75, 0.88, 1.0), metalness: 0.15, roughness: 0.06, clearcoat: 1, clearcoatRoughness: 0.04,
    iridescence: 1, iridescenceIOR: 1.7, iridescenceThicknessRange: [180, 620], emissive: accent.clone(), emissiveIntensity: 0.35, envMapIntensity: 1.7,
  });
  const core = new THREE.Mesh(new THREE.OctahedronGeometry(0.1, 0), coreMaterial);
  core.scale.set(1, 1.45, 1);
  const cageMaterial = new THREE.LineBasicMaterial({ color: hot(accent, 1.4), transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false });
  const cage = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(0.19, 1)), cageMaterial);
  const coreGroup = new THREE.Group();
  coreGroup.add(core, cage);
  coreGroup.position.y = TOP + 0.2;
  rig.add(coreGroup);
  const fingerprintMesh = new THREE.InstancedMesh(new THREE.BoxGeometry(0.012, 0.05, 0.012), new THREE.MeshBasicMaterial({ color: 0xffffff }), 16);
  const fingerprintRing = new THREE.Group();
  fingerprintRing.add(fingerprintMesh);
  fingerprintRing.position.y = TOP + 0.08;
  rig.add(fingerprintRing);
  let serverPrint = new Array(16).fill(0);
  function drawServerPrint() {
    for (let i = 0; i < 16; i++) {
      const angle = i / 16 * TAU;
      const height = 0.35 + serverPrint[i] / 255 * 1.3;
      quaternion.setFromAxisAngle(up, -angle);
      vector.set(Math.cos(angle) * 0.25, 0.025 * height, Math.sin(angle) * 0.25);
      matrix.compose(vector, quaternion, new THREE.Vector3(1, height, 1));
      fingerprintMesh.setMatrixAt(i, matrix);
      fingerprintMesh.setColorAt(i, hot(accent, 0.8 + serverPrint[i] / 255 * 2.4));
    }
    fingerprintMesh.instanceMatrix.needsUpdate = true;
    if (fingerprintMesh.instanceColor) fingerprintMesh.instanceColor.needsUpdate = true;
  }
  drawServerPrint();

  // The simulator's ring, and the rings of other tabs' pointers.
  const lensGeometry = new THREE.PlaneGeometry(0.6, 0.6);
  lensGeometry.rotateX(-Math.PI / 2);
  const makeLens = (color) => {
    const material = new THREE.ShaderMaterial({
      vertexShader: LENS_VERTEX,
      fragmentShader: LENS_FRAGMENT,
      uniforms: { uTime: { value: 0 }, uColor: { value: color }, uStrength: { value: 0 } },
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      side: THREE.DoubleSide,
    });
    const mesh = new THREE.Mesh(lensGeometry, material);
    mesh.position.y = TOP + 0.05;
    mesh.renderOrder = 4;
    rig.add(mesh);
    return mesh;
  };
  const lens = makeLens(hot(warnColor, 1.1));

  // Peers: a hexagonal node with a state ring, its name plate, and its links.
  const nodeGeometry = new THREE.CylinderGeometry(0.075, 0.082, 0.07, 6, 1);
  const nodeTopGeometry = new THREE.CylinderGeometry(0.058, 0.058, 0.006, 6, 1);
  const nodeRingGeometry = new THREE.TorusGeometry(0.1, 0.006, 8, 48);
  const bodyMaterial = new THREE.MeshPhysicalMaterial({ color: new THREE.Color(0.2, 0.24, 0.3), metalness: 0.9, roughness: 0.3, clearcoat: 0.7, clearcoatRoughness: 0.12, envMapIntensity: 1.2 });
  function makeNode() {
    const group = new THREE.Group();
    const body = new THREE.Mesh(nodeGeometry, bodyMaterial);
    const screenMaterial = new THREE.MeshBasicMaterial({ color: new THREE.Color(0, 0, 0) });
    const screen = new THREE.Mesh(nodeTopGeometry, screenMaterial);
    screen.position.y = 0.037;
    const ringMaterial = new THREE.MeshBasicMaterial({ color: new THREE.Color(0, 0, 0), transparent: true, blending: THREE.AdditiveBlending, depthWrite: false });
    const ring = new THREE.Mesh(nodeRingGeometry, ringMaterial);
    ring.rotation.x = Math.PI / 2;
    const name = plate(monoFont);
    const label = new THREE.Sprite(new THREE.SpriteMaterial({ map: name.texture, transparent: true, depthWrite: false, opacity: 0 }));
    label.scale.set(0.6, 0.12, 1);
    label.position.y = 0.19;
    label.renderOrder = 6;
    group.add(body, screen, ring, label);
    group.visible = false;
    rig.add(group);
    return { group, body, screen, screenMaterial, ring, ringMaterial, label, name };
  }

  const rand = random(0x0d7e4e7);
  const maxPeers = small ? 7 : 11;
  const slots = Array.from({ length: SLOTS }, (_, index) => ({ index, angle: index / SLOTS * TAU, gen: 0, peer: null, lamp: 0 }));
  const peers = [];
  for (let i = 0; i < maxPeers; i++) {
    peers.push({
      index: i, link: i, slot: null, gen: 0, state: 'empty', since: 0, radius: 1, height: 0.2, angle: 0,
      mismatch: false, print: [], node: makeNode(), acks: new Float32Array(ACK_BITS).fill(-1), received: 0,
      nextState: 0, nextReliable: 0, nextAck: 0, nextHello: 0, ackPulse: 0, bob: rand() * TAU,
    });
  }
  const remotes = [];
  for (let i = 0; i < REMOTE_LIMIT; i++) {
    remotes.push({
      index: i, link: SLOTS + i, id: null, gen: 0, state: 'empty', since: 0, print: [], hidden: false, lastHeard: 0,
      node: makeNode(), acks: new Float32Array(ACK_BITS).fill(-1), received: 0, rtt: null, color: new THREE.Color(),
      lens: makeLens(new THREE.Color()), lensLocal: new THREE.Vector3(), lensSeq: -1, lensAt: -99, helloSent: false,
      nextHello: 0, hue: 0,
    });
  }

  // Links: two lanes for each peer, as camera-facing ribbons rebuilt every frame in world space.
  const laneCount = MAX_LINKS * 2;
  const vertexCount = laneCount * SAMPLES * 2;
  const linkPositions = new Float32Array(vertexCount * 3);
  const linkColors = new Float32Array(vertexCount * 3);
  const linkUvs = new Float32Array(vertexCount * 2);
  const linkLanes = new Float32Array(vertexCount);
  const linkIndex = [];
  for (let lane = 0; lane < laneCount; lane++) {
    for (let k = 0; k < SAMPLES; k++) {
      const base = (lane * SAMPLES + k) * 2;
      linkUvs.set([k / (SAMPLES - 1), 0, k / (SAMPLES - 1), 1], base * 2);
      linkLanes[base] = linkLanes[base + 1] = lane % 2;
      if (k < SAMPLES - 1) linkIndex.push(base, base + 1, base + 2, base + 1, base + 3, base + 2);
    }
  }
  const linkGeometry = new THREE.BufferGeometry();
  linkGeometry.setAttribute('position', new THREE.BufferAttribute(linkPositions, 3).setUsage(THREE.DynamicDrawUsage));
  linkGeometry.setAttribute('aColor', new THREE.BufferAttribute(linkColors, 3).setUsage(THREE.DynamicDrawUsage));
  linkGeometry.setAttribute('uv', new THREE.BufferAttribute(linkUvs, 2));
  linkGeometry.setAttribute('aLane', new THREE.BufferAttribute(linkLanes, 1));
  linkGeometry.setIndex(linkIndex);
  const linkUniforms = { uTime: { value: 0 } };
  const links = new THREE.Mesh(linkGeometry, new THREE.ShaderMaterial({
    vertexShader: LINK_VERTEX, fragmentShader: LINK_FRAGMENT, uniforms: linkUniforms,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, side: THREE.DoubleSide,
  }));
  links.frustumCulled = false;
  links.renderOrder = 3;
  scene.add(links);
  // Each link's lanes, sampled in world space; packets ride these.
  const lanes = Array.from({ length: laneCount }, () => Array.from({ length: SAMPLES }, () => new THREE.Vector3()));
  const laneActive = new Uint8Array(laneCount);

  // Packets.
  const capsuleMesh = new THREE.InstancedMesh(new THREE.CapsuleGeometry(0.014, 0.05, 4, 10), new THREE.MeshBasicMaterial({ color: 0xffffff }), MAX_PACKETS);
  const beadMesh = new THREE.InstancedMesh(new THREE.SphereGeometry(0.013, 10, 8), new THREE.MeshBasicMaterial({ color: 0xffffff }), MAX_PACKETS);
  for (const mesh of [capsuleMesh, beadMesh]) {
    mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    mesh.setColorAt(0, new THREE.Color());
    mesh.instanceColor.setUsage(THREE.DynamicDrawUsage);
    mesh.frustumCulled = false;
    mesh.renderOrder = 5;
    scene.add(mesh);
  }
  const packets = Array.from({ length: MAX_PACKETS }, () => ({ active: false }));
  const resends = [];

  // Hello packets carry a fingerprint: a ring of sixteen bars around the packet. Acknowledgement
  // fields hang under the peers. Both are billboards drawn in world space.
  const bitsMesh = new THREE.InstancedMesh(new THREE.PlaneGeometry(1, 1), new THREE.MeshBasicMaterial({ color: 0xffffff, side: THREE.DoubleSide }), (maxPeers + REMOTE_LIMIT) * ACK_BITS);
  const printMesh = new THREE.InstancedMesh(new THREE.PlaneGeometry(1, 1), new THREE.MeshBasicMaterial({ color: 0xffffff, side: THREE.DoubleSide }), (maxPeers + REMOTE_LIMIT) * 16);
  for (const mesh of [bitsMesh, printMesh]) {
    mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    mesh.setColorAt(0, new THREE.Color());
    mesh.instanceColor.setUsage(THREE.DynamicDrawUsage);
    mesh.frustumCulled = false;
    mesh.renderOrder = 6;
    scene.add(mesh);
  }

  // Sparks: what a lost packet leaves, and the flare when fingerprints match.
  const sparkGeometry = new THREE.BufferGeometry();
  const sparkPositions = new Float32Array(MAX_SPARKS * 3);
  const sparkColors = new Float32Array(MAX_SPARKS * 3);
  const sparkLife = new Float32Array(MAX_SPARKS);
  const sparkVelocity = new Float32Array(MAX_SPARKS * 3);
  const sparkDecay = new Float32Array(MAX_SPARKS);
  sparkGeometry.setAttribute('position', new THREE.BufferAttribute(sparkPositions, 3).setUsage(THREE.DynamicDrawUsage));
  sparkGeometry.setAttribute('aColor', new THREE.BufferAttribute(sparkColors, 3).setUsage(THREE.DynamicDrawUsage));
  sparkGeometry.setAttribute('aLife', new THREE.BufferAttribute(sparkLife, 1).setUsage(THREE.DynamicDrawUsage));
  const sparkUniforms = { uPixel: { value: 10 } };
  const sparks = new THREE.Points(sparkGeometry, new THREE.ShaderMaterial({
    vertexShader: SPARK_VERTEX, fragmentShader: SPARK_FRAGMENT, uniforms: sparkUniforms,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  }));
  sparks.frustumCulled = false;
  sparks.renderOrder = 7;
  scene.add(sparks);
  let sparkCursor = 0;
  function burst(position, color, count, speed) {
    for (let n = 0; n < count; n++) {
      const i = sparkCursor;
      sparkCursor = (sparkCursor + 1) % MAX_SPARKS;
      sparkPositions.set([position.x, position.y, position.z], i * 3);
      const theta = rand() * TAU;
      const phi = Math.acos(rand() * 2 - 1);
      const v = speed * (0.4 + rand() * 0.6);
      sparkVelocity.set([Math.sin(phi) * Math.cos(theta) * v, Math.cos(phi) * v, Math.sin(phi) * Math.sin(theta) * v], i * 3);
      sparkColors.set([color.r, color.g, color.b], i * 3);
      sparkLife[i] = 1;
      sparkDecay[i] = 1.4 + rand() * 1.2;
    }
  }

  // Lights: a cool key, a rim, the accent from behind, and the pointer's lamp.
  const key = new THREE.DirectionalLight(new THREE.Color(0.86, 0.92, 1.0), 1.5);
  key.position.set(-4, 6, 6);
  const rim = new THREE.DirectionalLight(new THREE.Color(0.7, 0.85, 1.0), 2.2);
  rim.position.set(5, 3, -6);
  const back = new THREE.DirectionalLight(accent, 1.6);
  back.position.set(-6, -1, -4);
  const lamp = new THREE.PointLight(new THREE.Color(1.0, 0.95, 0.85), 0, 0, 2);
  scene.add(key, rim, back, lamp);

  // Post-processing.
  const postScene = new THREE.Scene();
  const postCamera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);
  const postQuad = new THREE.Mesh(quad);
  postQuad.frustumCulled = false;
  postScene.add(postQuad);
  const brightMaterial = fullscreenMaterial(BRIGHT_FRAGMENT, { tInput: { value: sceneTarget.texture }, uThreshold: { value: 0.95 } });
  const blurMaterial = fullscreenMaterial(BLUR_FRAGMENT, { tInput: { value: null }, uDirection: { value: new THREE.Vector2() } });
  const copyMaterial = fullscreenMaterial(/* glsl */ `
    uniform sampler2D tInput;
    varying vec2 vUv;
    void main() { gl_FragColor = texture2D(tInput, vUv); }
  `, { tInput: { value: null } });
  const compositeMaterial = fullscreenMaterial(COMPOSITE_FRAGMENT, {
    tScene: { value: sceneTarget.texture },
    tBloomNear: { value: bloomTargets[0].texture },
    tBloomFar: { value: bloomTargets[2].texture },
    uTime: { value: 0 },
  });
  function pass(material, target) {
    postQuad.material = material;
    renderer.setRenderTarget(target);
    renderer.render(postScene, postCamera);
  }
  function blur(target, scratch, radius) {
    blurMaterial.uniforms.tInput.value = target.texture;
    blurMaterial.uniforms.uDirection.value.set(radius / target.width, 0);
    pass(blurMaterial, scratch);
    blurMaterial.uniforms.tInput.value = scratch.texture;
    blurMaterial.uniforms.uDirection.value.set(0, radius / target.height);
    pass(blurMaterial, target);
  }

  // Layout -----------------------------------------------------------------------------------------

  let width = 1;
  let height = 1;
  let scale = 1;
  let dpr = 1;
  let place = { x: 0, y: 0, size: 0, above: false };
  const quality = { level: 1, slow: 0 };
  const anchor = new THREE.Vector3();
  const raycaster = new THREE.Raycaster();
  const zPlane = new THREE.Plane(new THREE.Vector3(0, 0, 1), 0);
  const ndc = new THREE.Vector2();

  function layout() {
    const rect = root.getBoundingClientRect();
    width = Math.max(1, Math.round(rect.width));
    height = Math.max(1, Math.round(rect.height));
    dpr = Math.min(window.devicePixelRatio || 1, small ? 1.5 : 1.75) * quality.level;
    renderer.setPixelRatio(dpr);
    renderer.setSize(width, height, false);
    const w = Math.max(1, Math.floor(width * dpr));
    const h = Math.max(1, Math.floor(height * dpr));
    sceneTarget.setSize(w, h);
    bloomTargets[0].setSize(Math.max(1, w >> 2), Math.max(1, h >> 2));
    bloomTargets[1].setSize(Math.max(1, w >> 2), Math.max(1, h >> 2));
    bloomTargets[2].setSize(Math.max(1, w >> 3), Math.max(1, h >> 3));
    bloomTargets[3].setSize(Math.max(1, w >> 3), Math.max(1, h >> 3));
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    camera.updateMatrixWorld();
    skyUniforms.uResolution.value.set(width, height);

    place = placement(root);
    placeStill();
    ndc.set(place.x / width * 2 - 1, -(place.y / height * 2 - 1));
    raycaster.setFromCamera(ndc, camera);
    raycaster.ray.intersectPlane(zPlane, anchor);
    const unitsPerPixel = 2 * camera.position.distanceTo(anchor) * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) / height;
    scale = Math.max(0.05, place.size * unitsPerPixel / MARK.height);
    rig.scale.setScalar(scale);
    sparkUniforms.uPixel.value = h / (2 * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2))) * 0.06 * scale;
    skyUniforms.uCenter.value.set(place.x / width, 1 - place.y / height);
    skyUniforms.uRadius.value = place.size / height * 0.7;
    const artWidth = place.size * MARK_ASPECT;
    skyUniforms.uHalf.value.set(artWidth / 2 / width, place.size / 2 / height);
    if (place.above) skyUniforms.uClip.value.set(0, 1 - (place.y + place.size * 0.58) / height, 1, 1);
    else skyUniforms.uClip.value.set((place.x - artWidth * 0.56) / width, 0, 1, 1);
    skyUniforms.uBits.value = small ? 0.065 : 0.085;
  }

  // Positions --------------------------------------------------------------------------------------

  const local = new THREE.Vector3();
  const world = new THREE.Vector3();
  const tangent = new THREE.Vector3();
  const side = new THREE.Vector3();
  const toCamera = new THREE.Vector3();
  const cameraRight = new THREE.Vector3();
  const cameraUp = new THREE.Vector3();
  const p0 = new THREE.Vector3();
  const p1 = new THREE.Vector3();
  const p2 = new THREE.Vector3();
  const p3 = new THREE.Vector3();
  const outward = new THREE.Vector3();
  const across = new THREE.Vector3();
  const edgeLocal = new THREE.Vector3();

  function socketLocal(slot, target) {
    return target.set(Math.cos(slot.angle) * DRUM.socket, TOP + 0.02, Math.sin(slot.angle) * DRUM.socket);
  }

  function bezier(t, target) {
    const s = 1 - t;
    return target.set(0, 0, 0)
      .addScaledVector(p0, s * s * s)
      .addScaledVector(p1, 3 * s * s * t)
      .addScaledVector(p2, 3 * s * t * t)
      .addScaledVector(p3, t * t * t);
  }

  // A link's two lanes, in world space, from a socket (p0) to a peer (p3) in rig space.
  function sampleLink(link, from, to, lift, sag) {
    outward.set(to.x - from.x, 0, to.z - from.z);
    if (outward.lengthSq() < 1e-8) outward.set(1, 0, 0);
    outward.normalize();
    across.crossVectors(outward, up);
    if (across.lengthSq() < 1e-8) across.set(0, 0, 1);
    across.normalize();
    for (let lane = 0; lane < 2; lane++) {
      const offset = (lane === 0 ? 1 : -1) * 0.013;
      p0.copy(from).addScaledVector(across, offset);
      p3.copy(to).addScaledVector(across, offset);
      p1.copy(p0).addScaledVector(up, lift).addScaledVector(outward, 0.08);
      p2.copy(p3).addScaledVector(outward, -0.18).addScaledVector(up, sag);
      const samples = lanes[link * 2 + lane];
      for (let k = 0; k < SAMPLES; k++) {
        bezier(k / (SAMPLES - 1), samples[k]);
        samples[k].applyMatrix4(rig.matrixWorld);
      }
    }
  }

  function writeRibbon(link, colorReliable, colorUnreliable, widthScale) {
    for (let lane = 0; lane < 2; lane++) {
      const index = link * 2 + lane;
      const samples = lanes[index];
      const color = lane === 0 ? colorReliable : colorUnreliable;
      laneActive[index] = color ? 1 : 0;
      const half = (lane === 0 ? 0.016 : 0.013) * scale * widthScale;
      for (let k = 0; k < SAMPLES; k++) {
        const previous = samples[Math.max(0, k - 1)];
        const next = samples[Math.min(SAMPLES - 1, k + 1)];
        tangent.subVectors(next, previous);
        toCamera.subVectors(camera.position, samples[k]);
        side.crossVectors(tangent, toCamera);
        if (side.lengthSq() < 1e-12) side.set(1, 0, 0);
        side.normalize().multiplyScalar(half);
        const base = ((index * SAMPLES + k) * 2) * 3;
        linkPositions[base] = samples[k].x - side.x;
        linkPositions[base + 1] = samples[k].y - side.y;
        linkPositions[base + 2] = samples[k].z - side.z;
        linkPositions[base + 3] = samples[k].x + side.x;
        linkPositions[base + 4] = samples[k].y + side.y;
        linkPositions[base + 5] = samples[k].z + side.z;
        // Links fade in from the socket end and towards the peer.
        const along = k / (SAMPLES - 1);
        const fade = color ? ease(along * 6) * (0.55 + 0.45 * (1 - along)) : 0;
        for (let v = 0; v < 2; v++) {
          linkColors[base + v * 3] = color ? color.r * fade : 0;
          linkColors[base + v * 3 + 1] = color ? color.g * fade : 0;
          linkColors[base + v * 3 + 2] = color ? color.b * fade : 0;
        }
      }
    }
  }

  function laneAt(link, lane, t, target, tangentTarget) {
    const samples = lanes[link * 2 + lane];
    const f = clamp01(t) * (SAMPLES - 1);
    const k = Math.min(SAMPLES - 2, Math.floor(f));
    const u = f - k;
    target.lerpVectors(samples[k], samples[k + 1], u);
    if (tangentTarget) tangentTarget.subVectors(samples[k + 1], samples[k]);
    return target;
  }

  // Packets ----------------------------------------------------------------------------------------

  // kind: 'state' (unreliable), 'event' (reliable), 'resend', 'hello', 'ack', 'chat' (another tab's
  // burst), 'idle'. dir 1 runs from the server out to the peer, -1 back.
  let seq = SEQ_START;
  let seqWrapGlow = 0;
  function send(owner, kind, dir, options = {}) {
    // A hidden tab draws nothing, so it keeps no packets in flight to flood back later.
    if (document.hidden) return null;
    const packet = packets.find((candidate) => !candidate.active);
    if (!packet) return null;
    const reliable = kind === 'event' || kind === 'resend' || kind === 'hello' || kind === 'chat';
    Object.assign(packet, {
      active: true, owner, kind, dir, reliable, lane: reliable ? 0 : 1, t: 0,
      speed: (options.speed || 0.85) * (0.9 + rand() * 0.2), dying: 0,
      lossAt: options.lossless ? 2 : (rand() < (options.loss ?? 0.04) ? 0.3 + rand() * 0.5 : 2),
      wobble: rand() * TAU, touched: false, jitter: 0, fade: options.fade || 0,
    });
    if (dir > 0 && owner.link !== LISTEN_LINK) {
      seq = (seq + 1) & 0xffff;
      if (seq === 0) seqWrapGlow = 1;
    }
    return packet;
  }

  function packetColor(packet, target) {
    switch (packet.kind) {
      case 'event': return target.copy(accent).multiplyScalar(3.4);
      case 'resend': return target.copy(warnColor).multiplyScalar(3.2);
      case 'hello': return target.setRGB(0.92, 0.88, 1.0).multiplyScalar(3.0);
      case 'ack': return target.copy(okColor).multiplyScalar(2.2);
      case 'chat': return target.copy(packet.owner.color || accent).multiplyScalar(3.8);
      case 'idle': return target.copy(infoColor).multiplyScalar(1.5);
      default: return target.setRGB(0.8, 0.92, 1.0).multiplyScalar(2.0);
    }
  }

  // An acknowledgement field takes the newest packet's fate at its front.
  function acknowledge(owner, received) {
    owner.acks.copyWithin(1, 0, ACK_BITS - 1);
    owner.acks[0] = received ? 1 : 0;
  }

  function delivered(packet) {
    const owner = packet.owner;
    if (packet.dir > 0) {
      if (owner.link === LISTEN_LINK) return;
      acknowledge(owner, true);
      if (packet.reliable) {
        owner.received += 1;
        // A burst gets an immediate acknowledgement after every sixteen packets.
        if (owner.burst > 0) {
          owner.burst -= 1;
          if (owner.burst % BURST === 0) {
            send(owner, 'ack', -1, { lossless: true, speed: 1.4 });
            owner.ackPulse = 1;
          }
        }
      }
    } else if (packet.kind === 'ack' || packet.kind === 'hello') {
      if (owner.slot) owner.slot.lamp = 1;
    } else if (packet.kind === 'chat') {
      coreFlare = 1;
    } else if (owner.slot) {
      owner.slot.lamp = Math.max(owner.slot.lamp, 0.5);
    }
  }

  function lost(packet, position) {
    burst(position, packet.kind === 'resend' ? hot(warnColor, 3) : hot(dangerColor, 2.4), 7, 0.25 * scale);
    if (packet.dir > 0 && packet.owner.link !== LISTEN_LINK) acknowledge(packet.owner, false);
    // Reliable events are sent again until acknowledged; unreliable ones are gone.
    if (packet.reliable && packet.kind !== 'hello') resends.push({ owner: packet.owner, dir: packet.dir, at: time + 0.35, kind: packet.kind === 'chat' ? 'chat' : 'resend' });
  }

  // The lifecycle ---------------------------------------------------------------------------------

  let nextLifecycle = 1.5;
  let serverHex = '';

  // A free slot well away from the taken ones, so peers spread round the drum.
  function freeSlot() {
    const taken = slots.filter((slot) => slot.peer || RESERVED.has(slot.index));
    let best = null;
    let bestScore = -Infinity;
    for (const slot of slots) {
      if (slot.peer || RESERVED.has(slot.index)) continue;
      let nearest = Math.PI;
      for (const other of taken) nearest = Math.min(nearest, Math.abs(Math.atan2(Math.sin(slot.angle - other.angle), Math.cos(slot.angle - other.angle))));
      const score = nearest + rand() * 0.35;
      if (score > bestScore) {
        best = slot;
        bestScore = score;
      }
    }
    return best;
  }

  function connect(peer, instant) {
    const slot = freeSlot();
    if (!slot) return;
    slot.peer = peer;
    slot.gen += 1;
    peer.slot = slot;
    peer.gen = slot.gen;
    peer.angle = slot.angle + (rand() - 0.5) * 0.12;
    // Behind the drum peers stand higher, in front of it farther out, so neither hides in it.
    const depth = Math.sin(peer.angle);
    peer.radius = 1.02 + rand() * 0.22 + Math.max(0, depth) * 0.22 - Math.max(0, -depth) * 0.1;
    peer.height = 0.12 + rand() * 0.26 + Math.max(0, -depth) * 0.16;
    peer.mismatch = !instant && rand() < 0.2;
    peer.print = peer.mismatch ? Array.from({ length: 16 }, () => Math.floor(rand() * 256)) : serverPrint.slice();
    peer.acks.fill(-1);
    peer.received = 0;
    peer.burst = 0;
    peer.state = instant ? 'connected' : 'arriving';
    peer.since = time;
    peer.nextState = time + rand() * 0.4;
    peer.nextReliable = time + 0.6 + rand() * 1.6;
    peer.nextAck = time + rand() * 0.3;
    peer.nextHello = time;
    if (instant) for (let i = 0; i < 20; i++) peer.acks[i] = rand() < 0.92 ? 1 : 0;
  }

  function release(peer) {
    if (peer.slot) peer.slot.peer = null;
    peer.slot = null;
    peer.state = 'empty';
    peer.node.group.visible = false;
  }

  function lifecycle() {
    const live = peers.filter((peer) => peer.state !== 'empty');
    const connected = peers.filter((peer) => peer.state === 'connected');
    const empty = peers.filter((peer) => peer.state === 'empty');
    const target = maxPeers - 2;
    if (empty.length && (live.length < target || rand() < 0.45)) connect(empty[Math.floor(rand() * empty.length)], false);
    else if (connected.length > 3) {
      const leaving = connected[Math.floor(rand() * connected.length)];
      leaving.state = 'leaving';
      leaving.since = time;
    }
    nextLifecycle = time + 3.2 + rand() * 3.2;
  }

  // Tabs -------------------------------------------------------------------------------------------

  const tabId = Math.random().toString(16).slice(2, 10);
  let bus = null;
  let busTimer = 0;
  let pointerSeq = 0;
  let lastPointerSent = 0;
  let coreFlare = 0;
  let listenNext = 1.2;
  const remoteGens = new Map();
  // A tab whose schema did not match is not heard again for a while.
  const refused = new Map();

  function remoteFor(id) {
    return remotes.find((remote) => remote.id === id && remote.state !== 'empty');
  }

  function busSend(message, visual) {
    if (!bus) return;
    bus.send({ ...message, from: tabId, wire: WIRE_VERSION, print: serverHex });
    // Every message the tab sends crosses the listening socket's link, as a packet.
    if (visual) {
      for (const remote of remotes) {
        if (remote.state === 'empty') continue;
        if (message.to && message.to !== remote.id) continue;
        send(remote, visual, 1, { lossless: true, speed: 1.1 });
      }
    }
  }

  function hueOf(id) {
    let hash = 0;
    for (const char of id) hash = Math.imul(hash ^ char.charCodeAt(0), 0x01000193) >>> 0;
    return (hash % 360) / 360;
  }

  function onMessage(message) {
    if (!message || typeof message !== 'object' || message.from === tabId || typeof message.from !== 'string') return;
    if ((refused.get(message.from) || 0) > wall()) return;
    let remote = remoteFor(message.from);
    const now = time;
    if (!remote) {
      if (message.type === 'bye') return;
      const free = remotes.find((candidate) => candidate.state === 'empty');
      if (!free) return;
      remote = free;
      remote.id = message.from;
      remote.gen = (remoteGens.get(message.from) || 0) + 1;
      remoteGens.set(message.from, remote.gen);
      remote.state = 'handshake';
      remote.since = wall();
      remote.helloSent = false;
      remote.rtt = null;
      remote.acks.fill(-1);
      remote.hue = hueOf(message.from);
      remote.color.setHSL(remote.hue, 0.85, 0.62);
      remote.lens.material.uniforms.uColor.value.copy(remote.color).multiplyScalar(1.5);
      remote.lensAt = -99;
      remote.nextHello = now;
      remote.print = [];
    }
    remote.lastHeard = now;
    remote.heard = wall();
    remote.hidden = Boolean(message.hidden);
    if (typeof message.print === 'string' && /^[0-9a-f]{32}$/.test(message.print)) {
      remote.print = message.print.match(/../g).map((pair) => parseInt(pair, 16));
      remote.mismatch = message.print !== serverHex || message.wire !== WIRE_VERSION;
    }
    const arrive = (kind) => send(remote, kind, -1, { lossless: true, speed: 1.1 });
    switch (message.type) {
      case 'hello':
        arrive('hello');
        if (!remote.helloSent) {
          remote.helloSent = true;
          busSend({ type: 'hello', to: message.from, hidden: document.hidden }, 'hello');
        }
        break;
      case 'idle':
        arrive('idle');
        acknowledge(remote, true);
        if (!remote.helloSent) {
          remote.helloSent = true;
          busSend({ type: 'hello', to: message.from, hidden: document.hidden }, 'hello');
        }
        break;
      case 'pointer':
        if (message.to && message.to !== tabId) break;
        if (typeof message.seq === 'number' && remote.lensSeq >= 0 && !seqNewer(message.seq, remote.lensSeq)) break;
        remote.lensSeq = message.seq;
        if (Number.isFinite(message.x) && Number.isFinite(message.z)) {
          remote.lensLocal.set(Math.max(-1.8, Math.min(1.8, message.x)), TOP + 0.05, Math.max(-1.8, Math.min(1.8, message.z)));
          remote.lensAt = now;
        }
        if (rand() < 0.35) arrive('state');
        break;
      case 'chat': {
        const count = Math.min(BURST, Math.max(1, message.count | 0));
        if (!document.hidden) for (let i = 0; i < count; i++) resends.push({ owner: remote, dir: -1, at: now + i * 0.06, kind: 'chat' });
        busSend({ type: 'ack', to: message.from, count }, 'ack');
        break;
      }
      case 'ack':
        if (message.to === tabId) {
          arrive('ack');
          acknowledge(remote, true);
        }
        break;
      case 'ping':
        if (message.to === tabId) busSend({ type: 'pong', to: message.from, sent: message.sent }, null);
        break;
      case 'pong':
        if (message.to === tabId && Number.isFinite(message.sent)) remote.rtt = performance.now() - message.sent;
        break;
      case 'bye':
        remote.state = 'leaving';
        remote.since = wall();
        break;
      default:
        break;
    }
    // Without motion there is no handshake to watch: a tab is simply there, or gone.
    if (reduceMotion) {
      if (remote.state === 'handshake' && remote.print.length === 16) remote.state = remote.mismatch ? 'mismatch' : 'connected';
      if (remote.state === 'leaving') forget(remote);
      requestFrame(true);
    }
  }

  function forget(remote) {
    remote.state = 'empty';
    remote.id = null;
    remote.node.group.visible = false;
  }

  function busTick() {
    busSend({ type: 'idle', hidden: document.hidden }, 'idle');
    for (const remote of remotes) {
      if (remote.state === 'empty') continue;
      if (remote.state === 'leaving' && wall() - remote.since > 1.3) {
        forget(remote);
        continue;
      }
      if (remote.state === 'connected') busSend({ type: 'ping', to: remote.id, sent: performance.now() }, null);
      const limit = remote.hidden ? 120 : 5;
      if (remote.state !== 'leaving' && wall() - remote.heard > limit) {
        remote.state = 'leaving';
        remote.since = wall();
        if (reduceMotion) forget(remote);
      }
    }
    // Which other tabs this one sees, for anyone curious enough to inspect the art.
    root.dataset.peers = remotes.filter((remote) => remote.state !== 'empty').map((remote) => `${SLOTS + remote.index}:${remote.gen} ${remote.state}`).join(', ');
    if (reduceMotion) requestFrame(true);
  }

  // The frame --------------------------------------------------------------------------------------

  const pointer = new THREE.Vector2(0, 0);
  let pointerActive = false;
  let lastPointer = 0;
  let presence = 0;
  const lensLocal = new THREE.Vector3(0, TOP + 0.05, 0);
  let lensStrength = 0;
  const lean = new THREE.Vector2();
  const drumPlane = new THREE.Plane();
  const planeNormal = new THREE.Vector3();
  const planePoint = new THREE.Vector3();
  const hit = new THREE.Vector3();
  const lampPosition = new THREE.Vector3();
  const color = new THREE.Color();
  const scratch = new THREE.Color();
  const packetPosition = new THREE.Vector3();
  const packetTangent = new THREE.Vector3();
  const lensWorld = new THREE.Vector3();
  const nodeWorld = new THREE.Vector3();
  const dummyScale = new THREE.Vector3();
  const hidden = new THREE.Matrix4().makeScale(0, 0, 0);
  const zAxis = new THREE.Vector3(0, 0, 1);
  const spin = new THREE.Quaternion();
  const lenses = [];

  function pointerOnDrum(ndcPoint, target) {
    raycaster.setFromCamera(ndcPoint, camera);
    planeNormal.set(0, 1, 0).applyQuaternion(rig.quaternion);
    planePoint.set(0, TOP + 0.05, 0).applyMatrix4(rig.matrixWorld);
    drumPlane.setFromNormalAndCoplanarPoint(planeNormal, planePoint);
    if (!raycaster.ray.intersectPlane(drumPlane, hit)) return false;
    rig.worldToLocal(target.copy(hit));
    return true;
  }

  function onPointer(event) {
    const rect = root.getBoundingClientRect();
    pointer.set((event.clientX - rect.left) / rect.width * 2 - 1, -((event.clientY - rect.top) / rect.height * 2 - 1));
    pointerActive = true;
    lastPointer = performance.now();
  }
  function onPress(event) {
    onPointer(event);
    if (!pointerOnDrum(pointer, local)) return;
    // The nearest connected peer gets a burst of sixteen reliable events.
    let nearest = null;
    let nearestDistance = Infinity;
    for (const peer of peers) {
      if (peer.state !== 'connected') continue;
      const distance = Math.hypot(Math.cos(peer.angle) * peer.radius - local.x, Math.sin(peer.angle) * peer.radius - local.z);
      if (distance < nearestDistance) {
        nearest = peer;
        nearestDistance = distance;
      }
    }
    if (nearest) {
      nearest.burst = (nearest.burst || 0) + BURST;
      for (let i = 0; i < BURST; i++) resends.push({ owner: nearest, dir: 1, at: time + i * 0.045, kind: 'event' });
    }
    busSend({ type: 'chat', count: BURST }, 'chat');
  }
  function onLeave() {
    pointerActive = false;
  }
  const hero = root.closest('.dw-hero') || root;
  if (!reduceMotion) {
    hero.addEventListener('pointermove', onPointer, { passive: true });
    hero.addEventListener('pointerdown', onPress, { passive: true });
    hero.addEventListener('pointerleave', onLeave, { passive: true });
  }

  const clock = new THREE.Clock();
  let time = reduceMotion ? 7.3 : 0;
  let visible = false;
  let frameHandle = 0;
  let first = true;
  let contextLost = false;

  // Start with most slots taken, a couple still arriving.
  for (let i = 0; i < maxPeers - 3; i++) connect(peers[i], true);
  connect(peers[maxPeers - 3], false);

  const labelColor = (state, remote) => {
    if (state === 'mismatch') return [css(dangerColor), css(dangerColor)];
    if (state === 'handshake' || state === 'arriving') return ['rgba(230, 225, 255, 0.9)', 'rgba(235, 232, 255, 1)'];
    if (remote) return [css(remote.color), css(remote.color)];
    return [css(accent, 0.8), 'rgba(226, 233, 240, 0.95)'];
  };

  function simulate(dt) {
    // Peers.
    for (const peer of peers) {
      if (peer.state === 'empty') continue;
      const age = time - peer.since;
      if (peer.state === 'arriving' && age > 0.8) {
        peer.state = 'handshake';
        peer.since = time;
      } else if (peer.state === 'handshake') {
        if (time >= peer.nextHello) {
          send(peer, 'hello', -1, { lossless: true });
          if (age > 0.2) send(peer, 'hello', 1, { lossless: true });
          peer.nextHello = time + 0.3;
        }
        if (age > HANDSHAKE_TIME) {
          peer.state = peer.mismatch ? 'mismatch' : 'connected';
          peer.since = time;
          laneAt(peer.link, 0, 1, packetPosition);
          burst(packetPosition, peer.mismatch ? hot(dangerColor, 3) : hot(accent, 3.2), 16, 0.35 * scale);
          peer.nextState = time + 0.2;
        }
      } else if (peer.state === 'mismatch') {
        // The server keeps a mismatched client for mismatch_linger, sending only its hello.
        if (time >= peer.nextHello) {
          send(peer, 'hello', 1, { lossless: true });
          peer.nextHello = time + 0.3;
        }
        if (age > MISMATCH_LINGER) {
          peer.state = 'leaving';
          peer.since = time;
        }
      } else if (peer.state === 'connected') {
        if (time >= peer.nextState) {
          send(peer, 'state', rand() < 0.5 ? 1 : -1, { loss: 0.05 });
          peer.nextState = time + 0.22 + rand() * 0.3;
        }
        if (time >= peer.nextReliable) {
          send(peer, 'event', rand() < 0.6 ? 1 : -1, { loss: 0.06 });
          peer.nextReliable = time + 1.0 + rand() * 2.2;
        }
        if (time >= peer.nextAck) {
          send(peer, 'ack', -1, { loss: 0.02, speed: 1.2 });
          peer.nextAck = time + 0.45 + rand() * 0.4;
        }
      } else if (peer.state === 'leaving' && age > 1.3) {
        release(peer);
      }
      peer.ackPulse = Math.max(0, peer.ackPulse - dt * 1.6);
    }
    if (time >= nextLifecycle) lifecycle();

    // Resends and bursts, when their time comes.
    for (let i = resends.length - 1; i >= 0; i--) {
      const resend = resends[i];
      if (time < resend.at) continue;
      resends.splice(i, 1);
      const owner = resend.owner;
      if (owner.state !== 'connected' && owner.state !== 'handshake') continue;
      send(owner, resend.kind, resend.dir, { loss: resend.kind === 'chat' ? 0 : 0.04, speed: resend.kind === 'event' ? 1.05 : 1.0 });
    }

    // Other tabs.
    for (const remote of remotes) {
      if (remote.state === 'empty') continue;
      const age = wall() - remote.since;
      if (remote.state === 'handshake') {
        if (time >= remote.nextHello) {
          send(remote, 'hello', 1, { lossless: true, speed: 1.1 });
          remote.nextHello = time + 0.3;
        }
        if (age > HANDSHAKE_TIME && remote.print.length === 16) {
          remote.state = remote.mismatch ? 'mismatch' : 'connected';
          remote.since = wall();
          laneAt(remote.link, 0, 1, packetPosition);
          burst(packetPosition, remote.mismatch ? hot(dangerColor, 3) : hot(remote.color, 3.4), 22, 0.4 * scale);
          coreFlare = Math.max(coreFlare, 0.7);
        }
      } else if (remote.state === 'mismatch' && age > MISMATCH_LINGER) {
        refused.set(remote.id, wall() + 20);
        remote.state = 'leaving';
        remote.since = wall();
      } else if (remote.state === 'leaving' && age > 1.3) {
        forget(remote);
      }
    }

    // The listening socket's lonely hello, when nobody answers.
    if (!remotes.some((remote) => remote.state !== 'empty') && time >= listenNext) {
      const packet = send({ link: LISTEN_LINK, acks: null, slot: null }, 'hello', 1, { lossless: true, speed: 0.42, fade: 1 });
      if (packet) packet.lonely = true;
      listenNext = time + 2.6 + rand() * 1.4;
    }

    // Your pointer's ring, to the other tabs.
    if (bus && lensStrength > 0.3 && performance.now() - lastPointerSent > 70 && remotes.some((remote) => remote.state === 'connected')) {
      lastPointerSent = performance.now();
      pointerSeq = (pointerSeq + 1) & 0xffff;
      busSend({ type: 'pointer', seq: pointerSeq, x: +lensLocal.x.toFixed(4), z: +lensLocal.z.toFixed(4) }, rand() < 0.3 ? 'state' : null);
    }
  }

  function frame() {
    frameHandle = 0;
    if (contextLost) return;
    const rawDt = clock.getDelta();
    const dt = Math.min(rawDt, 0.05);
    if (!reduceMotion && rawDt < 0.5) {
      quality.slow = rawDt > 1 / 40 ? quality.slow + rawDt : Math.max(0, quality.slow - rawDt * 0.5);
      if (quality.slow > 1.5 && quality.level > 0.5) {
        quality.level = Math.max(0.5, quality.level - 0.2);
        quality.slow = 0;
        layout();
      }
    }
    if (!reduceMotion) time += dt;
    skyUniforms.uTime.value = time;
    linkUniforms.uTime.value = time;
    compositeMaterial.uniforms.uTime.value = time;

    // The rig, leaning a little towards the pointer and breathing.
    const idle = !pointerActive || performance.now() - lastPointer > 4000;
    const follow = reduceMotion ? 1 : Math.min(1, dt * 2.5);
    lean.x += ((idle ? 0 : THREE.MathUtils.clamp(-pointer.y * 0.07, -0.08, 0.08)) - lean.x) * follow;
    lean.y += ((idle ? 0 : THREE.MathUtils.clamp(pointer.x * 0.12, -0.12, 0.12)) - lean.y) * follow;
    rig.position.set(anchor.x - MARK.x * scale, anchor.y - MARK.y * scale + Math.sin(time * 0.6) * 0.012 * scale, anchor.z);
    rig.rotation.set(TILT + lean.x + Math.sin(time * 0.31) * 0.012, lean.y + Math.sin(time * 0.23) * 0.04 - 0.1, 0);
    rig.updateMatrixWorld(true);
    cameraRight.setFromMatrixColumn(camera.matrixWorld, 0);
    cameraUp.setFromMatrixColumn(camera.matrixWorld, 1);

    // The pointer's lamp and the simulator's ring.
    // The ring only stands on the network: beyond the peers the pointer is just a pointer.
    const wantLens = !idle && pointerOnDrum(pointer, hit) && Math.hypot(hit.x, hit.z) < 1.75;
    if (wantLens) {
      hit.y = TOP + 0.05;
      lensLocal.lerp(hit, reduceMotion || lensStrength < 0.05 ? 1 : Math.min(1, dt * 10));
    }
    lensStrength += ((wantLens ? 1 : 0) - lensStrength) * (reduceMotion ? 1 : Math.min(1, dt * 4));
    lens.position.copy(lensLocal);
    lens.material.uniforms.uStrength.value = lensStrength;
    lens.material.uniforms.uTime.value = time;
    lens.visible = lensStrength > 0.01;
    presence += ((idle ? 0.3 : 1) - presence) * (reduceMotion ? 1 : Math.min(1, dt * 3));
    if (idle) lampPosition.set(Math.sin(time * 0.37) * 1.2, TOP + 0.9, Math.cos(time * 0.29) * 1.1 + 0.6).applyMatrix4(rig.matrixWorld);
    else lens.getWorldPosition(lampPosition).addScaledVector(planeNormal.set(0, 1, 0).applyQuaternion(rig.quaternion), 0.7 * scale);
    lamp.position.lerp(lampPosition, reduceMotion ? 1 : Math.min(1, dt * 6));
    lamp.intensity = presence * 14 * scale * scale;

    simulate(dt);

    // The drum's details.
    const phase = Math.floor((time * 1.4) % 4);
    for (let i = 0; i < 4; i++) frameMesh.setColorAt(i, i === phase ? hot(accent, 3) : hot(accent, 0.12));
    frameMesh.instanceColor.needsUpdate = true;
    dial.rotation.y = -time * 0.05;
    seqWrapGlow = Math.max(0, seqWrapGlow - dt * 0.8);
    bezelMaterial.emissiveIntensity = seqWrapGlow * 1.6;
    const lit = seq % tickCount;
    for (let i = 0; i < tickCount; i++) {
      const distance = (lit - i + tickCount) % tickCount;
      ticks.setColorAt(i, distance === 0 ? hot(accent, 4) : distance < 5 ? hot(accent, 1.4 - distance * 0.25) : hot(infoColor, 0.3 + seqWrapGlow * 1.5));
    }
    ticks.instanceColor.needsUpdate = true;
    for (const slot of slots) {
      const peer = slot.peer;
      slot.lamp = Math.max(0, slot.lamp - dt * 2.2);
      let base = null;
      if (peer) {
        if (peer.state === 'connected') base = hot(okColor, 1.2 + slot.lamp * 1.2);
        else if (peer.state === 'mismatch') base = hot(dangerColor, 1.6);
        else if (peer.state === 'leaving') base = hot(dangerColor, 0.5 * (1 - (time - peer.since) / 1.3));
        else base = hot(warnColor, 1.4 + slot.lamp);
      }
      lampMesh.setColorAt(slot.index, base || scratch.setRGB(0.02, 0.025, 0.03));
      for (let j = 0; j < 4; j++) notchMesh.setColorAt(slot.index * 4 + j, j < Math.min(4, slot.gen) ? hot(infoColor, j === Math.min(4, slot.gen) - 1 && peer ? 1.8 : 0.5) : scratch.setRGB(0.015, 0.02, 0.025));
    }
    lampMesh.instanceColor.needsUpdate = true;
    notchMesh.instanceColor.needsUpdate = true;
    coreFlare = Math.max(0, coreFlare - dt * 0.9);
    coreGroup.rotation.y = time * 0.35;
    coreGroup.position.y = TOP + 0.2 + Math.sin(time * 1.1) * 0.012;
    cage.rotation.set(time * 0.13, -time * 0.5, 0);
    coreMaterial.emissiveIntensity = 0.35 + coreFlare * 2.2;
    cageMaterial.opacity = 0.45 + coreFlare * 0.5;
    fingerprintRing.rotation.y = -time * 0.18;
    const listening = remotes.some((remote) => remote.state !== 'empty');
    const breath = 0.5 + 0.5 * Math.sin(time * TAU * 0.35);
    portRingMaterial.color.copy(listening ? okColor : accent).multiplyScalar(listening ? 2.4 : 0.6 + breath * 1.6);

    // Nodes, links and name plates.
    let bitCursor = 0;
    let printCursor = 0;
    const drawEntry = (entry, isRemote) => {
      const node = entry.node;
      if (entry.state === 'empty') {
        node.group.visible = false;
        return;
      }
      const age = (isRemote ? wall() : time) - entry.since;
      let appear = 1;
      let drift = 0;
      if (entry.state === 'arriving') appear = ease(age / 0.8);
      if (entry.state === 'leaving') {
        appear = 1 - ease(age / 1.3);
        drift = ease(age / 1.3) * 0.7;
      }
      if (isRemote) {
        const spread = (entry.index - (REMOTE_LIMIT - 1) / 2) * 0.42;
        local.set(1.42 + drift, 0.2 + entry.index * 0.05, spread * 0.9 - 0.08);
        if (entry.state === 'handshake') local.x += (1 - ease(age / 0.6)) * 0.6;
      } else {
        const radius = entry.radius + drift + (1 - appear) * 1.2;
        local.set(Math.cos(entry.angle) * radius, entry.height + Math.sin(time * 0.9 + entry.bob) * 0.02, Math.sin(entry.angle) * radius);
      }
      node.group.visible = true;
      node.group.position.copy(local);
      node.group.rotation.y = time * 0.4 + entry.index;
      node.group.scale.setScalar(Math.max(0.001, appear));
      let ringColor;
      let lane0;
      let lane1;
      const tint = isRemote ? entry.color : accent;
      if (entry.state === 'connected') {
        ringColor = hot(tint, 1.6 + (entry.ackPulse || 0) * 2);
        lane0 = hot(tint, 1.05);
        lane1 = scratch.setRGB(0.7, 0.86, 1.0).multiplyScalar(0.5).clone();
      } else if (entry.state === 'mismatch') {
        ringColor = hot(dangerColor, 2.2);
        lane0 = hot(dangerColor, 1.1);
        lane1 = null;
      } else if (entry.state === 'leaving') {
        ringColor = hot(dangerColor, appear);
        lane0 = hot(infoColor, 0.5 * appear);
        lane1 = hot(infoColor, 0.3 * appear);
      } else {
        const pulse = 0.6 + 0.4 * Math.sin(time * TAU * 0.8);
        ringColor = scratch.setRGB(0.9, 0.86, 1.0).multiplyScalar(1.6 * pulse).clone();
        lane0 = scratch.setRGB(0.85, 0.82, 1.0).multiplyScalar(0.7 * appear).clone();
        lane1 = null;
      }
      node.ringMaterial.color.copy(ringColor);
      node.screenMaterial.color.copy(ringColor).multiplyScalar(0.8);
      const [stroke, fill] = labelColor(entry.state, isRemote ? entry : null);
      const name = isRemote
        ? `peer ${SLOTS + entry.index}:${entry.gen}${entry.rtt != null && entry.state === 'connected' ? ` · ${entry.rtt < 10 ? entry.rtt.toFixed(1) : Math.round(entry.rtt)} ms` : ''}`
        : `peer ${entry.slot ? entry.slot.index : 0}:${entry.gen}`;
      node.name.draw(entry.state === 'mismatch' ? 'SchemaMismatch' : name, stroke, fill);
      node.label.material.opacity = appear * (small ? 0.85 : 0.95);
      node.label.scale.set(0.6, 0.12, 1);

      // The link: from the socket to the node, or for another tab, from the listening socket.
      if (isRemote) local.copy(port.position).add(p0.set(0.03, 0, 0));
      else socketLocal(entry.slot, local.set(0, 0, 0));
      const from = local.clone();
      const to = node.group.position.clone().add(p0.set(0, -0.02, 0));
      if (isRemote) sampleLink(entry.link, from, to, 0.05, 0.12);
      else sampleLink(entry.link, from, to, 0.3, 0.06);
      writeRibbon(entry.link, lane0, lane1, isRemote ? 1.2 : 1);

      // The acknowledgement field under the node, and the fingerprint while it says hello.
      node.group.getWorldPosition(nodeWorld);
      const cell = 0.0105 * scale;
      for (let i = 0; i < ACK_BITS; i++) {
        const value = entry.acks[i];
        vector.copy(nodeWorld).addScaledVector(cameraRight, (i - (ACK_BITS - 1) / 2) * cell * 1.35).addScaledVector(cameraUp, -0.115 * scale);
        matrix.compose(vector, camera.quaternion, dummyScale.set(cell, cell * 1.8, 1).multiplyScalar(appear));
        bitsMesh.setMatrixAt(bitCursor, matrix);
        bitsMesh.setColorAt(bitCursor, value < 0 ? scratch.setRGB(0.03, 0.04, 0.05) : value > 0 ? hot(okColor, i === 0 ? 2.4 : 1.1) : hot(dangerColor, 1.4));
        bitCursor += 1;
      }
      const showPrint = entry.state === 'arriving' || entry.state === 'handshake' || entry.state === 'mismatch';
      const print = entry.print && entry.print.length === 16 ? entry.print : null;
      for (let i = 0; i < 16; i++) {
        if (!showPrint || !print) {
          printMesh.setMatrixAt(printCursor++, hidden);
          continue;
        }
        const angle = i / 16 * TAU + time * 0.8;
        const length = (0.3 + print[i] / 255) * 0.03 * scale;
        vector.copy(nodeWorld)
          .addScaledVector(cameraRight, Math.cos(angle) * 0.14 * scale)
          .addScaledVector(cameraUp, Math.sin(angle) * 0.14 * scale);
        quaternion.copy(camera.quaternion).multiply(spin.setFromAxisAngle(zAxis, angle - Math.PI / 2));
        matrix.compose(vector, quaternion, dummyScale.set(0.008 * scale, length, 1).multiplyScalar(appear));
        printMesh.setMatrixAt(printCursor, matrix);
        const same = print[i] === serverPrint[i];
        printMesh.setColorAt(printCursor, entry.state === 'mismatch' || !same ? hot(dangerColor, 1.8) : hot(isRemote ? entry.color : accent, 2.2));
        printCursor += 1;
      }
    };
    for (const peer of peers) {
      if (peer.state === 'empty') writeRibbon(peer.link, null, null, 1);
      drawEntry(peer, false);
    }
    for (const remote of remotes) {
      if (remote.state === 'empty') writeRibbon(remote.link, null, null, 1);
      drawEntry(remote, true);
      const recent = remote.state === 'connected' && time - remote.lensAt < 2.5;
      const strength = remote.lens.material.uniforms.uStrength;
      strength.value += ((recent ? 1 : 0) - strength.value) * Math.min(1, dt * 4);
      remote.lens.visible = strength.value > 0.01;
      remote.lens.position.lerp(remote.lensLocal, Math.min(1, dt * 12));
      remote.lens.material.uniforms.uTime.value = time;
    }
    for (let i = bitCursor; i < bitsMesh.count; i++) bitsMesh.setMatrixAt(i, hidden);
    for (let i = printCursor; i < printMesh.count; i++) printMesh.setMatrixAt(i, hidden);
    bitsMesh.instanceMatrix.needsUpdate = true;
    bitsMesh.instanceColor.needsUpdate = true;
    printMesh.instanceMatrix.needsUpdate = true;
    printMesh.instanceColor.needsUpdate = true;

    // The listening socket's link: out to the page's edge, at the socket's height on screen.
    port.getWorldPosition(world);
    vector.copy(world).project(camera);
    ndc.set(1.08, vector.y);
    raycaster.setFromCamera(ndc, camera);
    zPlane.constant = -world.z;
    if (raycaster.ray.intersectPlane(zPlane, edgeLocal)) rig.worldToLocal(edgeLocal);
    zPlane.constant = 0;
    p3.copy(edgeLocal);
    sampleLink(LISTEN_LINK, local.copy(port.position).add(p0.set(0.03, 0, 0)), p3.clone(), 0.02, -0.04);
    const listenGlow = listening ? 0.9 : 0.25 + breath * 0.25;
    writeRibbon(LISTEN_LINK, null, hot(listening ? okColor : infoColor, listenGlow), 0.8);
    linkGeometry.attributes.position.needsUpdate = true;
    linkGeometry.attributes.aColor.needsUpdate = true;

    // Packets along their lanes.
    let capsules = 0;
    let beads = 0;
    lenses.length = 0;
    if (lensStrength > 0.2) lenses.push(lensLocal);
    for (const remote of remotes) if (remote.lens.visible && remote.lens.material.uniforms.uStrength.value > 0.2) lenses.push(remote.lens.position);
    for (const packet of packets) {
      if (!packet.active) continue;
      const owner = packet.owner;
      const listen = owner.link === LISTEN_LINK;
      const base = owner.link * 2;
      let lane = listen ? 1 : packet.lane;
      if (!listen && !laneActive[base + lane]) lane = laneActive[base] ? 0 : laneActive[base + 1] ? 1 : -1;
      if (lane < 0) {
        packet.active = false;
        continue;
      }
      const along = packet.dir > 0 ? packet.t : 1 - packet.t;
      laneAt(owner.link, lane, along, packetPosition, packetTangent);
      // The simulator: packets crossing a pointer's ring are delayed, shaken, duplicated or lost.
      let slow = 1;
      if (lenses.length) rig.worldToLocal(lensWorld.copy(packetPosition));
      for (const center of lenses) {
        const distance = Math.hypot(lensWorld.x - center.x, lensWorld.z - center.z);
        if (distance < 0.33) {
          slow = Math.min(slow, 0.45);
          packet.jitter = Math.min(1, packet.jitter + dt * 4);
          if (!packet.touched) {
            packet.touched = true;
            const roll = rand();
            if (roll < 0.3 && !listen && packet.lossAt > 1) packet.lossAt = packet.t + 0.03;
            else if (roll < 0.45 && !listen) {
              const copy = send(owner, packet.kind, packet.dir, { lossless: true, speed: packet.speed });
              if (copy) {
                copy.t = Math.max(0, packet.t - 0.06);
                copy.touched = true;
              }
            }
          }
        }
      }
      packet.jitter = Math.max(0, packet.jitter - dt * 1.2);
      if (!reduceMotion) packet.t += dt * packet.speed * slow;
      if (packet.jitter > 0) packetPosition.addScaledVector(cameraUp, Math.sin(time * 38 + packet.wobble) * 0.02 * scale * packet.jitter);
      if (packet.t >= packet.lossAt) {
        packet.active = false;
        lost(packet, packetPosition);
        continue;
      }
      if (packet.t >= 1) {
        packet.active = false;
        delivered(packet);
        continue;
      }
      if (packet.dir < 0) packetTangent.negate();
      let size = packet.kind === 'hello' ? 1.3 : packet.kind === 'chat' ? 1.35 : 1;
      if (packet.fade) size *= 1 - ease((packet.t - 0.55) / 0.45);
      packetColor(packet, color);
      if (packet.fade) color.multiplyScalar(1 - ease((packet.t - 0.4) / 0.6));
      if (packet.reliable) {
        if (packetTangent.lengthSq() < 1e-12) packetTangent.set(0, 1, 0);
        quaternion.setFromUnitVectors(up, packetTangent.normalize());
        matrix.compose(packetPosition, quaternion, dummyScale.setScalar(scale * size));
        capsuleMesh.setMatrixAt(capsules, matrix);
        capsuleMesh.setColorAt(capsules, color);
        capsules += 1;
      } else {
        matrix.compose(packetPosition, quaternion.identity(), dummyScale.setScalar(scale * size * (packet.kind === 'ack' ? 0.7 : 1)));
        beadMesh.setMatrixAt(beads, matrix);
        beadMesh.setColorAt(beads, color);
        beads += 1;
      }
    }
    capsuleMesh.count = capsules;
    beadMesh.count = beads;
    for (const mesh of [capsuleMesh, beadMesh]) {
      mesh.instanceMatrix.needsUpdate = true;
      mesh.instanceColor.needsUpdate = true;
    }

    // Sparks.
    const drag = Math.exp(-dt * 2.5);
    for (let i = 0; i < MAX_SPARKS; i++) {
      if (sparkLife[i] <= 0) continue;
      sparkLife[i] = Math.max(0, sparkLife[i] - dt * sparkDecay[i]);
      for (let a = 0; a < 3; a++) {
        sparkPositions[i * 3 + a] += sparkVelocity[i * 3 + a] * dt;
        sparkVelocity[i * 3 + a] *= drag;
      }
    }
    sparkGeometry.attributes.position.needsUpdate = true;
    sparkGeometry.attributes.aLife.needsUpdate = true;
    sparkGeometry.attributes.aColor.needsUpdate = true;

    // The scene, then the bloom and the composite.
    renderer.setRenderTarget(sceneTarget);
    renderer.clear();
    renderer.render(scene, camera);
    pass(brightMaterial, bloomTargets[0]);
    blur(bloomTargets[0], bloomTargets[1], 1.0);
    blur(bloomTargets[0], bloomTargets[1], 2.0);
    copyMaterial.uniforms.tInput.value = bloomTargets[0].texture;
    pass(copyMaterial, bloomTargets[2]);
    blur(bloomTargets[2], bloomTargets[3], 1.5);
    blur(bloomTargets[2], bloomTargets[3], 3.0);
    pass(compositeMaterial, null);

    if (first) {
      first = false;
      root.classList.add('is-live');
    }
    if (visible && !reduceMotion && !document.hidden) requestFrame();
  }

  function requestFrame(force) {
    if (frameHandle || contextLost) return;
    if (force && !visible) return;
    frameHandle = requestAnimationFrame(frame);
  }

  canvas.addEventListener('webglcontextlost', (event) => {
    event.preventDefault();
    contextLost = true;
    root.classList.remove('is-live');
  });
  canvas.addEventListener('webglcontextrestored', () => {
    if (bus) {
      bus.send({ type: 'bye', from: tabId });
      bus.close();
      bus = null;
    }
    clearInterval(busTimer);
    canvas.remove();
    still.remove();
    root.classList.remove('is-live', 'is-placed');
    for (const remote of remotes) remote.lens.removeFromParent();
    mount(root);
  });

  layout();
  // The drum and the handshake share one fingerprint: the schema's.
  fingerprint(SCHEMA).then((bytes) => {
    serverPrint = bytes;
    serverHex = toHex(bytes);
    drawServerPrint();
    for (const peer of peers) if (!peer.mismatch && peer.state !== 'empty') peer.print = bytes.slice();
    bus = openBus(onMessage);
    busSend({ type: 'hello', hidden: document.hidden }, null);
    busTimer = setInterval(busTick, BUS_IDLE * 1000);
    addEventListener('pagehide', () => {
      if (bus) bus.send({ type: 'bye', from: tabId });
    });
  });
  new ResizeObserver(() => {
    layout();
    requestFrame(true);
  }).observe(root);
  if (document.fonts) {
    document.fonts.ready.then(() => {
      layout();
      requestFrame(true);
    });
  }
  new IntersectionObserver((entries) => {
    visible = entries.some((entry) => entry.isIntersecting);
    if (visible) {
      clock.getDelta();
      requestFrame(true);
    }
  }).observe(root);
  document.addEventListener('visibilitychange', () => {
    if (bus) busSend({ type: 'idle', hidden: document.hidden }, null);
    // A frame asked for while hidden may never come; ask again when the tab is back.
    if (document.hidden && frameHandle) {
      cancelAnimationFrame(frameHandle);
      frameHandle = 0;
    }
    if (!document.hidden && visible) {
      clock.getDelta();
      requestFrame(true);
    }
  });
}

for (const root of document.querySelectorAll('[data-dw-hero-art]')) mount(root);
