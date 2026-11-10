#!/usr/bin/env node
/**
 * สร้าง/ตรวจ Content-Security-Policy ของหน้าคอนโซล (index.html) — GitHub Pages ตั้ง header เองไม่ได้ จึงใช้ <meta http-equiv>
 *
 *   node tools/csp.cjs            อัปเดตแท็ก CSP ใน index.html ให้ตรงกับสคริปต์ปัจจุบัน
 *   node tools/csp.cjs --check    ตรวจเฉยๆ (ออกด้วยรหัส 1 ถ้าแท็กไม่ตรง) — รันก่อน commit ได้
 *   --file <path>                 ใช้กับไฟล์อื่น (เช่นสำเนาสำหรับทดสอบ)   --connect <origin>  เพิ่มปลายทางที่หน้าเว็บเรียกได้ (ซ้ำได้)
 *
 * ทำไมต้องรันทุกครั้งที่แก้ <script>: สคริปต์ในหน้านี้เป็น inline จึงอนุญาตด้วยค่า hash (sha256) ของเนื้อหาแต่ละบล็อก
 * แก้แม้ตัวอักษรเดียว hash เปลี่ยน แล้วเบราว์เซอร์จะ "ไม่รัน" สคริปต์ — หน้าจะค้างว่างเปล่า (ดูที่ Console ของเบราว์เซอร์จะเห็นข้อความ CSP)
 * ผลที่ได้: สคริปต์ที่ใครแทรกเข้ามาในหน้า (XSS) จะไม่ถูกรัน และข้อมูลส่งออกได้เฉพาะปลายทางที่ระบุใน connect-src
 */
const fs = require('node:fs');
const crypto = require('node:crypto');

const args = process.argv.slice(2);
const opt = (name, d) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : d; };
const file = opt('--file', require('node:path').join(__dirname, '..', 'index.html'));
const check = args.includes('--check');
const extra = args.flatMap((a, i) => (a === '--connect' ? [args[i + 1]] : []));

const raw = fs.readFileSync(file, 'utf8');
const CRLF = raw.includes('\r\n');
const s = raw.split('\r\n').join('\n');     // HTML parser แปลง CRLF เป็น LF ก่อนคำนวณ hash ของสคริปต์ จึงต้องใช้ LF

// สคริปต์ inline ทุกบล็อก (ไม่มี src)
const scripts = [...s.matchAll(/<script(?![^>]*\bsrc\b)[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
if (!scripts.length) throw new Error('ไม่พบ <script> ในไฟล์');
const hashes = scripts.map(t => `'sha256-${crypto.createHash('sha256').update(t, 'utf8').digest('base64')}'`);

// ปลายทางที่หน้าเว็บเรียก (fetch): API บน Railway + Supabase Auth ตาม window.CDM_CONFIG, และ Worker ของระบบเดิม (ใช้ตอนย้อนกลับ — ลบออกเมื่อปิดระบบเดิมแล้ว)
const origin = u => { try { return new URL(u).origin; } catch { return null; } };
const cfg = s.match(/window\.CDM_CONFIG\s*=\s*\{[^}]*\}/);
const fromCfg = key => { const m = cfg && cfg[0].match(new RegExp(key + String.raw`\s*:\s*"([^"]+)"`)); return m ? origin(m[1]) : null; };
const legacy = [...s.matchAll(/https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.workers\.dev/g)].map(m => m[0]);
const connect = [...new Set([fromCfg('apiBase'), fromCfg('supabaseUrl'), ...legacy, ...extra.map(origin)].filter(Boolean))];

const policy = [
  `default-src 'none'`,
  `script-src ${hashes.join(' ')}`,                 // เฉพาะสคริปต์ inline ที่ hash ตรง — ไม่มี 'unsafe-inline' ไม่มี eval ไม่โหลดสคริปต์ภายนอก
  `style-src 'unsafe-inline' https://fonts.googleapis.com`,   // หน้านี้ใช้ style="" จำนวนมาก (hash ใช้กับ attribute ไม่ได้)
  `font-src https://fonts.gstatic.com`,
  `img-src 'self' data: blob:`,
  `connect-src ${connect.join(' ')}`,
  `base-uri 'none'`,
  `form-action 'none'`,
  `object-src 'none'`,
].join('; ');

const tag = `<meta http-equiv="Content-Security-Policy" content="${policy}">`;
const re = /<meta http-equiv="Content-Security-Policy"[^>]*>/i;
let out;
if (re.test(s)) out = s.replace(re, () => tag);
else {
  const vp = /<meta name="viewport"[^>]*>/i;
  if (!vp.test(s)) throw new Error('ไม่พบ <meta name="viewport"> ให้วาง CSP ต่อท้าย');
  out = s.replace(vp, m => m + '\n' + tag);
}

if (check) {
  if (out === s) { console.log(`CSP ตรงกับสคริปต์ (${hashes.length} บล็อก, connect: ${connect.join(' ')})`); process.exit(0); }
  console.error('CSP ไม่ตรงกับสคริปต์ปัจจุบัน — รัน: node tools/csp.cjs'); process.exit(1);
}
fs.writeFileSync(file, CRLF ? out.split('\n').join('\r\n') : out);
console.log(`อัปเดต CSP แล้ว: สคริปต์ ${hashes.length} บล็อก, connect-src = ${connect.join(' ')}`);
