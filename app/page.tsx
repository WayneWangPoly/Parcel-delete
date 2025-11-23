"use client";

import { useState } from "react";

type City = "Sydney" | "Melbourne" | "Adelaide" | "Perth" | "Brisbane";
type ModuleKey = "assign" | "activity" | "delete" | "upload";

const CITIES: City[] = ["Sydney", "Melbourne", "Adelaide", "Perth", "Brisbane"];

const MODULES: { key: ModuleKey; title: string; subtitle: string; description: string; emoji: string }[] = [
  {
    key: "assign",
    title: "任务分配",
    subtitle: "Task Assignment",
    description: "创建线路、分配区域和包裹给司机。",
    emoji: "📋",
  },
  {
    key: "activity",
    title: "任务动态",
    subtitle: "Task Activity",
    description: "实时查看司机进度与异常提醒。",
    emoji: "📡",
  },
  {
    key: "delete",
    title: "删除包裹",
    subtitle: "Delete Parcel",
    description: "扫码 / 输入编号删除异常包裹。",
    emoji: "🗑️",
  },
  {
    key: "upload",
    title: "上传照片",
    subtitle: "Upload Photos",
    description: "上传网络故障/异常投递证明照片。",
    emoji: "📷",
  },
];

export default function HomePage() {
  const [activeCity, setActiveCity] = useState<City>("Melbourne");
  const [activeModule, setActiveModule] = useState<ModuleKey>("delete");

  return (
    <main className="flex min-h-screen w-full items-start justify-center py-6 px-3">
      {/* 容器：模拟手机宽度 */}
      <div className="w-full max-w-md rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-950 via-slate-950/95 to-slate-900/90 shadow-2xl shadow-black/40 overflow-hidden">
        {/* 顶部栏 */}
        <header className="px-5 pt-4 pb-3 border-b border-slate-800/70 bg-slate-950/80 backdrop-blur">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              {/* Logo 圆形占位 */}
              <div className="h-9 w-9 rounded-2xl bg-emerald-500/10 border border-emerald-400/40 flex items-center justify-center text-emerald-300 font-semibold text-xl">
                ME
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-semibold tracking-wide text-slate-50">
                  MicroExpress
                </span>
                <span className="text-[11px] uppercase tracking-[0.18em] text-slate-400">
                  Admin Portal
                </span>
              </div>
            </div>

            <div className="flex flex-col items-end text-xs text-slate-400">
              <span className="text-[11px]">Logged in as</span>
              <span className="text-xs font-medium text-slate-100">
                Admin · #{activeCity}
              </span>
            </div>
          </div>
        </header>

        {/* 城市切换 */}
        <section className="px-5 pt-3 pb-2 border-b border-slate-800/70 bg-slate-950/70 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400">
              当前运营城市 / City
            </span>
          </div>
          <div className="flex gap-1.5 overflow-x-auto pb-1.5 hide-scrollbar">
            {CITIES.map((city) => {
              const active = city === activeCity;
              return (
                <button
                  key={city}
                  onClick={() => setActiveCity(city)}
                  className={[
                    "whitespace-nowrap rounded-full px-3 py-1.5 text-xs font-medium transition-all",
                    active
                      ? "bg-emerald-500 text-slate-950 shadow shadow-emerald-500/40"
                      : "bg-slate-900/80 text-slate-300 border border-slate-700 hover:border-emerald-400/60 hover:text-emerald-300",
                  ].join(" ")}
                >
                  {city}
                </button>
              );
            })}
          </div>
        </section>

        {/* 主功能模块网格 */}
        <section className="px-5 pt-4 pb-1">
          <div className="flex items-center justify-between mb-2">
            <h1 className="text-sm font-semibold text-slate-100">
              控制面板 / Dashboard
            </h1>
            <span className="text-[11px] text-slate-400">
              Tap a card to open module
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3">
            {MODULES.map((mod) => {
              const active = mod.key === activeModule;
              return (
                <button
                  key={mod.key}
                  onClick={() => setActiveModule(mod.key)}
                  className={[
                    "group flex h-28 flex-col items-start justify-between rounded-2xl border px-3.5 py-3 text-left transition-all",
                    "focus:outline-none focus:ring-2 focus:ring-emerald-400/70 focus:ring-offset-0",
                    active
                      ? "border-emerald-400/80 bg-emerald-500/10 shadow-lg shadow-emerald-500/30"
                      : "border-slate-800 bg-slate-900/60 hover:border-emerald-400/60 hover:bg-slate-900",
                  ].join(" ")}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xl">{mod.emoji}</span>
                    <div className="flex flex-col">
                      <span className="text-xs font-semibold text-slate-50">
                        {mod.title}
                      </span>
                      <span className="text-[10px] uppercase tracking-[0.14em] text-slate-400">
                        {mod.subtitle}
                      </span>
                    </div>
                  </div>
                  <p className="text-[11px] leading-snug text-slate-400 line-clamp-2">
                    {mod.description}
                  </p>
                </button>
              );
            })}
          </div>
        </section>

        {/* 模块内容区域 */}
        <section className="px-5 pb-5 pt-3">
          <ActiveModulePanel city={activeCity} module={activeModule} />
        </section>
      </div>
    </main>
  );
}

/**
 * 模块内容：这里只把「删除包裹」做成真正可用
 * 其它模块先保留占位（后面再填任务分配、任务动态等）
 */
function ActiveModulePanel({ city, module }: { city: City; module: ModuleKey }) {
  // ----- 通用：占位文案 -----
  if (module === "assign" || module === "activity" || module === "upload") {
    const titleMap: Record<ModuleKey, string> = {
      assign: "任务分配模块 · 即将上线",
      activity: "任务动态模块 · 即将上线",
      delete: "",
      upload: "上传照片模块 · 即将上线",
    };

    const hintMap: Record<ModuleKey, string> = {
      assign: "后续将在这里创建线路、分配区域和派单规则。",
      activity: "后续将在这里看到司机位置、进度、异常提醒。",
      delete: "",
      upload: "后续将在这里上传投递失败截图、网络故障证明等。",
    };

    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3.5">
        <div className="flex items-center justify-between mb-1.5">
          <h2 className="text-xs font-semibold text-slate-100">
            {titleMap[module]}
          </h2>
          <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300">
            City: {city}
          </span>
        </div>
        <p className="text-[11px] text-slate-400 mb-2.5">
          {hintMap[module]}
        </p>
        <div className="rounded-xl border border-dashed border-slate-700/80 bg-slate-900/60 px-3 py-2.5">
          <p className="text-[11px] text-slate-500">
            🔧 This area is a placeholder.
            <br />
            后面我们会在这里接入真正的功能：表单、上传控件、地图、司机列表等。
          </p>
        </div>
      </div>
    );
  }

  // ----- 删除包裹模块：集成「输入序号」+「上传截图」 -----

  return <DeleteModulePanel city={city} />;
}

/**
 * 删除包裹模块：支持
 * 1）手动输入多个 ME 编号
 * 2）上传截图，走 OCR 再调用删除接口
 */
function DeleteModulePanel({ city }: { city: City }) {
  // 手动删除状态
  const [barcodeInput, setBarcodeInput] = useState("");
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteResult, setDeleteResult] = useState<any | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  // 上传截图删除状态
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadPreview, setUploadPreview] = useState<string | null>(null);
  const [uploadLoading, setUploadLoading] = useState(false);
  const [uploadResult, setUploadResult] = useState<any | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // ===== 手动删件 =====
  async function handleDelete(e: React.FormEvent) {
    e.preventDefault();
    setDeleteError(null);
    setDeleteResult(null);

    const cleaned = barcodeInput
      .split(/[\s,;\n]+/)
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);

    if (!cleaned.length) {
      setDeleteError("Please enter at least one parcel ID.");
      return;
    }
    if (cleaned.length > 20) {
      setDeleteError("Maximum 20 IDs per batch.");
      return;
    }

    setDeleteLoading(true);
    try {
      const res = await fetch("/api/delete-parcel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          barcodes: cleaned,
          reason_code: "NOREASON",
          address_type: "house",
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setDeleteError(data?.message || "Delete request failed.");
      } else {
        setDeleteResult(data);
      }
    } catch (err: any) {
      setDeleteError(String(err));
    } finally {
      setDeleteLoading(false);
    }
  }

  // ===== 上传截图删件 =====
  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    setUploadError(null);
    setUploadResult(null);

    const file = e.target.files?.[0];
    if (!file) {
      setUploadFile(null);
      setUploadPreview(null);
      return;
    }
    setUploadFile(file);
    const url = URL.createObjectURL(file);
    setUploadPreview(url);
  }

  async function handleUpload(e: React.FormEvent) {
    e.preventDefault();
    setUploadError(null);
    setUploadResult(null);

    if (!uploadFile) {
      setUploadError("Please choose an image (screenshot or photo).");
      return;
    }

    const formData = new FormData();
    formData.append("file", uploadFile);

    setUploadLoading(true);
    try {
      const res = await fetch("/api/ocr-delete", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) {
        setUploadError(data?.message || "OCR & delete request failed.");
      } else {
        setUploadResult(data);
      }
    } catch (err: any) {
      setUploadError(String(err));
    } finally {
      setUploadLoading(false);
    }
  }

  // ===== 渲染删除结果（公共小组件） =====
  function renderDeleteSummary(result: any, compact?: boolean) {
    if (!result) return null;

    const total = result.total ?? result.items?.length ?? 0;
    const success = result.success ?? result.items?.filter((x: any) => x.ok).length ?? 0;
    const failed = result.failed ?? (total - success);

    const items = result.items ?? [];

    return (
      <div className={`mt-3 border-t border-slate-800 pt-2 ${compact ? "text-[11px]" : "text-xs"}`}>
        <div className="flex items-center justify-between mb-1">
          <span className="text-slate-400">
            Total: <span className="text-slate-100 font-medium">{total}</span>
          </span>
          <span className="text-emerald-400">
            ✅ {success} &nbsp;/&nbsp;
            <span className="text-red-400">❌ {failed}</span>
          </span>
        </div>

        <div className="space-y-1 max-h-32 overflow-auto pr-1">
          {items.map((item: any) => (
            <div
              key={item.barcode}
              className="flex items-center justify-between text-[11px] bg-slate-950/70 border border-slate-800 rounded-xl px-3 py-1.5"
            >
              <span className="font-mono text-[10px] text-slate-100 truncate">
                {item.barcode}
              </span>
              <span>
                {item.ok ? (
                  <span className="text-emerald-400">Deleted</span>
                ) : (
                  <span className="text-red-400">Failed</span>
                )}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // OCR 删除结果里，真正的删除结构在 data.delete 里
  const uploadDeleteResult = uploadResult?.delete ?? null;

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3.5">
      <div className="flex items-center justify-between mb-1.5">
        <h2 className="text-xs font-semibold text-slate-100">
          删除包裹 / Delete Parcels
        </h2>
        <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300">
          City: {city}
        </span>
      </div>
      <p className="text-[11px] text-slate-400 mb-3">
        支持手动输入序号，或上传截图自动识别 ME 编号，一键删除异常包裹。
      </p>

      {/* 区块 1：手动输入序号 */}
      <form onSubmit={handleDelete} className="mb-3 rounded-2xl border border-slate-800 bg-slate-950/70 px-3.5 py-3 space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold text-slate-100">
            方式一：输入序号
          </span>
          <span className="text-[10px] text-slate-500">
            支持多条（用空格/换行分隔）
          </span>
        </div>

        <textarea
          className="w-full h-20 rounded-2xl bg-slate-950 border border-slate-800 px-3 py-2 text-[11px] text-slate-100 resize-none focus:outline-none focus:ring-1 focus:ring-emerald-500/70"
          placeholder={"ME1762625646002VEF\nME1762015913619SCQ"}
          value={barcodeInput}
          onChange={(e) => setBarcodeInput(e.target.value)}
        />

        {deleteError && (
          <div className="text-[11px] text-red-400 bg-red-950/40 border border-red-800/60 rounded-xl px-3 py-1.5">
            {deleteError}
          </div>
        )}

        <button
          type="submit"
          disabled={deleteLoading}
          className="w-full rounded-2xl bg-emerald-500 text-slate-900 text-[11px] font-semibold py-2 disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {deleteLoading ? "Deleting…" : "Delete parcels"}
        </button>

        {renderDeleteSummary(deleteResult, true)}
      </form>

      {/* 区块 2：上传截图识别并删除 */}
      <form onSubmit={handleUpload} className="rounded-2xl border border-slate-800 bg-slate-950/70 px-3.5 py-3 space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold text-slate-100">
            方式二：上传截图
          </span>
          <span className="text-[10px] text-slate-500">
            支持条码截图 / 拍照
          </span>
        </div>

        <label className="flex items-center justify-between rounded-2xl bg-slate-950 border border-dashed border-slate-700 px-3 py-2 text-[11px] text-slate-400 cursor-pointer hover:border-emerald-400/80 hover:text-emerald-300 transition">
          <span>
            {uploadFile
              ? uploadFile.name
              : "点击选择图片（截图 / 照片）"}
          </span>
          <span className="text-emerald-400 text-[11px] font-semibold">
            Browse
          </span>
          <input
            type="file"
            accept="image/*"
            className="hidden"
            onChange={handleFileChange}
          />
        </label>

        {uploadPreview && (
          <div className="mt-1 rounded-2xl overflow-hidden border border-slate-800 max-h-52">
            <img
              src={uploadPreview}
              alt="preview"
              className="w-full object-contain max-h-52 bg-black"
            />
          </div>
        )}

        {uploadError && (
          <div className="text-[11px] text-red-400 bg-red-950/40 border border-red-800/60 rounded-xl px-3 py-1.5">
            {uploadError}
          </div>
        )}

        <button
          type="submit"
          disabled={uploadLoading}
          className="w-full rounded-2xl bg-emerald-500 text-slate-900 text-[11px] font-semibold py-2 disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {uploadLoading ? "Processing…" : "Process & delete"}
        </button>

        {/* 显示 OCR 识别到的 ID + 删除结果 */}
        {uploadResult && (
          <div className="mt-2 text-[11px] text-slate-300">
            <div className="mb-1.5">
              <span className="text-slate-400">Recognized IDs: </span>
              {uploadResult.recognized && uploadResult.recognized.length ? (
                <span className="font-mono text-[10px] text-emerald-400">
                  {uploadResult.recognized.join(", ")}
                </span>
              ) : (
                <span className="text-slate-500">none</span>
              )}
            </div>
            {renderDeleteSummary(uploadDeleteResult, true)}
          </div>
        )}
      </form>
    </div>
  );
}
