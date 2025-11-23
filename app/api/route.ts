import { NextResponse } from "next/server";
import crypto from "crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const AES_KEY = process.env.AES_KEY || "1236987410000111";
const AES_IV = process.env.AES_IV || "1236987410000111";
const API_BASE = process.env.API_BASE || "https://microexpress.com.au";
const API_DELETE = process.env.API_DELETE || "/smydriver/delete-sudo-parcel";

// ==== AES CBC 加密（让 Node 自己做 PKCS7 padding） ====
function encryptPayload(payload: any) {
  const jsonStr = JSON.stringify(payload);
  const data = Buffer.from(jsonStr, "utf8");

  const cipher = crypto.createCipheriv(
    "aes-128-cbc",
    Buffer.from(AES_KEY, "utf8"),
    Buffer.from(AES_IV, "utf8")
  );
  // 默认 autoPadding = true（即 PKCS7），刚好和 Python 版匹配

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return encrypted.toString("base64");
}

// ==== 请求后端 PHP 接口 ====
async function postDelete(barcode: string) {
  const payload = {
    bar_code: barcode.trim().toUpperCase(),
    reason_code: "NOREASON",
    address_type: "house",
    myme_timestamp: Date.now(),
  };

  const encrypted = encryptPayload(payload);

  let res: Response;
  try {
    res = await fetch(API_BASE + API_DELETE, {
      method: "POST",
      headers: {
        "Content-Type": "application/json;UTF-8",
        "User-Agent": "MicroExpress-NextJS",
        "Accept-Language": "en-AU,en;q=0.9",
      },
      body: JSON.stringify({ data: encrypted }),
    });
  } catch (e: any) {
    return {
      ok: false,
      backend: {
        stage: "network_error",
        message: e?.message || String(e),
      },
    };
  }

  const status = res.status;
  let text: string;
  try {
    text = await res.text();
  } catch (e: any) {
    return {
      ok: false,
      backend: {
        stage: "read_body_error",
        status,
        message: e?.message || String(e),
      },
    };
  }

  let js: any;
  try {
    js = JSON.parse(text);
  } catch {
    js = { raw: text }; // 不是 JSON，就当纯文本
  }

  const ok = status === 200 && js?.code === 200;

  return {
    ok,
    backend: {
      status,
      ...js,
    },
  };
}

// ==== 主入口 ====
export async function POST(req: Request) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const barcodes = body?.barcodes;
  if (!Array.isArray(barcodes) || barcodes.length === 0) {
    return NextResponse.json({ error: "No barcodes" }, { status: 400 });
  }

  const items: any[] = [];

  for (const raw of barcodes) {
    const code = String(raw || "").trim();
    if (!code) continue;

    const result = await postDelete(code);
    items.push({
      barcode: code,
      ok: result.ok,
      backend: result.backend,
    });
  }

  const successCount = items.filter((i) => i.ok).length;
  const failedCount = items.filter((i) => !i.ok).length;

  return NextResponse.json({
    total: items.length,
    success: successCount,
    failed: failedCount,
    items,
  });
}
