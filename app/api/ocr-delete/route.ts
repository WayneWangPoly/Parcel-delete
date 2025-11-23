// app/api/ocr-delete/route.ts
import crypto from "crypto";

export const runtime = "nodejs"; // 用 node 环境，方便 Buffer / crypto

const OCR_API_KEY = process.env.OCR_API_KEY || "";

// 提取条码用到的一些工具（和你之前 Python 逻辑类似）

const CHAR_REPL: Record<string, string> = {
  "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J",
  "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "У": "Y",
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
};

function normalizeText(s: string): string {
  return [...s].map(ch => CHAR_REPL[ch] ?? ch).join("");
}

function fixOcr(s: string): string {
  return normalizeText(s).toUpperCase();
}

function canonBarcode(raw: string): string | null {
  const s = fixOcr(raw);
  const m = s.match(/^ME([0-9OIL]{3})([0-9O]{10})([A-Z0-9O]{3})$/);
  if (!m) return null;
  let [_, series, mid10, last3] = m;
  series = series.replace(/I|L/g, "1").replace(/O/g, "0");
  mid10 = mid10.replace(/O/g, "0");
  if (!/^\d{3}$/.test(series) || !/^\d{10}$/.test(mid10)) return null;
  return `ME${series}${mid10}${last3}`;
}

function extractIdsFromText(text: string): string[] {
  const noSpace = fixOcr(text.replace(/\s+/g, ""));
  const matches = noSpace.match(/ME[0-9OIL]{3}[0-9O]{10}[A-Z0-9O]{3}/g) || [];
  const out: string[] = [];
  for (const m of matches) {
    const canon = canonBarcode(m);
    if (canon && !out.includes(canon)) out.push(canon);
  }
  console.log("[ocr-delete] extract", out);
  return out;
}

// ===== 调用 OCR.space =====

async function ocrImage(file: File): Promise<string | null> {
  if (!OCR_API_KEY) {
    console.error("[ocr-delete] Missing OCR_API_KEY");
    return null;
  }

  const buffer = Buffer.from(await file.arrayBuffer());

  const form = new FormData();
  form.append("apikey", OCR_API_KEY);
  form.append("language", "eng");
  form.append("isOverlayRequired", "false");
  form.append("OCREngine", "2");
  form.append(
    "file",
    new Blob([buffer], { type: file.type || "image/jpeg" }) as any,
    file.name || "image.jpg"
  );

  const res = await fetch("https://api.ocr.space/parse/image", {
    method: "POST",
    body: form,
  });

  if (!res.ok) {
    console.error("[ocr-delete] HTTP", res.status);
    return null;
  }

  const data = await res.json();
  if (data.IsErroredOnProcessing) {
    console.error("[ocr-delete] OCR error", data.ErrorMessage);
    return null;
  }

  const parsed = data.ParsedResults?.[0]?.ParsedText || "";
  console.log("[ocr-delete] text len", parsed.length);
  return parsed;
}

// ===== 主 Handler：上传图片 → OCR → 调用 /api/delete-parcel =====

export async function POST(req: Request) {
  try {
    const form = await req.formData();
    const file = form.get("file");

    if (!(file instanceof File)) {
      return Response.json(
        { code: 400, message: "No image file provided (field: file)" },
        { status: 400 }
      );
    }

    const text = await ocrImage(file);
    if (!text) {
      return Response.json(
        { code: 502, message: "OCR failed" },
        { status: 502 }
      );
    }

    const ids = extractIdsFromText(text);
    if (!ids.length) {
      return Response.json(
        { code: 404, message: "No parcel IDs found in image", ocrTextLength: text.length },
        { status: 404 }
      );
    }

    // 内部转调 /api/delete-parcel，复用你现有的删除逻辑
    const urlObj = new URL(req.url);
    urlObj.pathname = "/api/delete-parcel";
    urlObj.search = "";

    const res2 = await fetch(urlObj.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        barcodes: ids,
        reason_code: "NOREASON",
        address_type: "house",
      }),
    });

    const deleteResult = await res2.json().catch(() => ({}));

    return Response.json(
      {
        code: 200,
        message: "ocr_and_delete_done",
        recognized: ids,
        delete: deleteResult,
      },
      { status: 200 }
    );
  } catch (e: any) {
    console.error("[ocr-delete] error:", e);
    return Response.json(
      { code: 500, message: "internal_error", error: String(e) },
      { status: 500 }
    );
  }
}
