#!/usr/bin/env node
// Dependency-free generator for the marketplace icon (extension/media/icon.png).
// Draws a shield + checkmark on a dark rounded background, 4x supersampled for smooth
// edges, and encodes a 128x128 RGBA PNG with Node's zlib. Re-run: node scripts/gen-icon.js
import zlib from "zlib";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "extension", "media", "icon.png");
const SIZE = 128;
const SS = 4; // supersample factor
const W = SIZE * SS;

// --- geometry (in 128-space, scaled by SS) ---------------------------------
const s = (n) => n * SS;
const shield = [
  [30, 30], [98, 30], [98, 66], [88, 86], [64, 102], [40, 86], [30, 66],
].map(([x, y]) => [s(x), s(y)]);
const check = [[48, 64], [59, 76], [83, 50]].map(([x, y]) => [s(x), s(y)]);
const CHECK_W = s(7);

const BG = [13, 17, 23];        // #0d1117
const SHIELD_TOP = [63, 185, 80];  // #3fb950 GitHub green
const SHIELD_BOT = [35, 134, 54];  // darker green
const CHECK_COL = [255, 255, 255];
const RADIUS = s(24);

function pointInPoly(px, py, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i], [xj, yj] = poly[j];
    if ((yi > py) !== (yj > py) && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function distToSeg(px, py, [ax, ay], [bx, by]) {
  const dx = bx - ax, dy = by - ay;
  const len2 = dx * dx + dy * dy || 1;
  let t = ((px - ax) * dx + (py - ay) * dy) / len2;
  t = Math.max(0, Math.min(1, t));
  const cx = ax + t * dx, cy = ay + t * dy;
  return Math.hypot(px - cx, py - cy);
}

function inRoundedRect(px, py) {
  const r = RADIUS;
  if (px >= r && px <= W - r) return py >= 0 && py <= W;
  if (py >= r && py <= W - r) return px >= 0 && px <= W;
  const cx = px < r ? r : W - r;
  const cy = py < r ? r : W - r;
  return Math.hypot(px - cx, py - cy) <= r;
}

// --- render at full (supersampled) resolution -------------------------------
const hi = Buffer.alloc(W * W * 4);
for (let y = 0; y < W; y++) {
  for (let x = 0; x < W; x++) {
    let col = null, alpha = 0;
    if (inRoundedRect(x, y)) {
      col = BG; alpha = 255;
      if (pointInPoly(x, y, shield)) {
        const t = (y - s(30)) / (s(102) - s(30));
        col = SHIELD_TOP.map((c, i) => Math.round(c + (SHIELD_BOT[i] - c) * Math.max(0, Math.min(1, t))));
      }
      let cd = Infinity;
      for (let i = 0; i < check.length - 1; i++) cd = Math.min(cd, distToSeg(x, y, check[i], check[i + 1]));
      if (cd <= CHECK_W / 2) col = CHECK_COL;
    }
    const o = (y * W + x) * 4;
    if (col) { hi[o] = col[0]; hi[o + 1] = col[1]; hi[o + 2] = col[2]; hi[o + 3] = alpha; }
  }
}

// --- downsample SSxSS -> 1 (box filter) -------------------------------------
const raw = Buffer.alloc(SIZE * SIZE * 4);
for (let y = 0; y < SIZE; y++) {
  for (let x = 0; x < SIZE; x++) {
    let r = 0, g = 0, b = 0, a = 0;
    for (let dy = 0; dy < SS; dy++) for (let dx = 0; dx < SS; dx++) {
      const o = ((y * SS + dy) * W + (x * SS + dx)) * 4;
      r += hi[o]; g += hi[o + 1]; b += hi[o + 2]; a += hi[o + 3];
    }
    const n = SS * SS, o = (y * SIZE + x) * 4;
    raw[o] = Math.round(r / n); raw[o + 1] = Math.round(g / n); raw[o + 2] = Math.round(b / n); raw[o + 3] = Math.round(a / n);
  }
}

// --- PNG encode -------------------------------------------------------------
function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const body = Buffer.concat([typeBuf, data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}
const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0); ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
const stride = SIZE * 4;
const filtered = Buffer.alloc((stride + 1) * SIZE);
for (let y = 0; y < SIZE; y++) {
  filtered[y * (stride + 1)] = 0;
  raw.copy(filtered, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
}
const idat = zlib.deflateSync(filtered, { level: 9 });
const png = Buffer.concat([sig, chunk("IHDR", ihdr), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0))]);
fs.writeFileSync(OUT, png);
console.log(`✔ wrote ${path.relative(process.cwd(), OUT)} (${png.length} bytes, ${SIZE}x${SIZE})`);
