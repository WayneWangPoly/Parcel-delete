def sync_pipeline(form, quick_ids, req_id: str):
    """同步：仅返回【一条】WhatsApp消息：顶部是 ACK，下面接详细结果。
       （Twilio/WhatsApp 渠道一次 Webhook 只可靠发送 1 条 <Message>）"""
    try:
        incoming_msg = (form.get("Body") or "").strip()
        num_media    = int(form.get("NumMedia", 0))

        # 1) 先做识别（文本 + 媒体）
        parcel_ids = set(quick_ids)
        stats = []

        if num_media > 0 and quick_ids:
            ack_head = f"✅ Received {len(quick_ids)} ID(s) and 🖼️ {num_media} image(s). Working on it…"
        elif num_media > 0:
            ack_head = f"🖼️ Received {num_media} image(s). Working on it…"
        elif quick_ids:
            ack_head = f"✅ Received {len(quick_ids)} ID(s). Working on it…"
        else:
            ack_head = "👋 Message received. I’ll try to extract parcel IDs…"

        if incoming_msg and quick_ids:
            stats.append(f"Text: found {len(quick_ids)}")

        if num_media > 0:
            for i in range(num_media):
                media_url  = form.get(f"MediaUrl{i}", "")
                media_type = form.get(f"MediaContentType{i}", "")
                if not media_url or not media_type.startswith('image/'):
                    stats.append(f"Image {i+1}: not an image")
                    continue
                img = download_twilio_media(media_url)
                if not img:
                    stats.append(f"Image {i+1}: download failed")
                    continue
                before = len(parcel_ids)
                ids = process_image(img)
                for pid in ids: parcel_ids.add(pid)
                new_count = len(parcel_ids) - before
                stats.append(f"Image {i+1}: {'found' if ids else 'no IDs'} ({new_count} new)")

        if not parcel_ids:
            full_text = ack_head + "\n\n" + "❌ No parcel IDs found.\n💡 Send a clear screenshot or type: ME176XXXXXXXXXXABC"
            resp = MessagingResponse()
            resp.message(full_text)
            return Response(str(resp), mimetype="application/xml")

        parcel_list = sorted(parcel_ids)
        if len(parcel_list) > MAX_BATCH_SIZE:
            stats_report = "\n".join(stats)
            preview = '\n'.join([f"  • {p}" for p in parcel_list[:5]])
            full_text = (
                f"{ack_head}\n\n"
                f"⚠️ Too many IDs! ({len(parcel_list)})\n\n{stats_report}\n\n"
                f"Max per batch: {MAX_BATCH_SIZE}\n\nFirst 5:\n{preview}\n...\nPlease split into smaller batches."
            )
            resp = MessagingResponse()
            resp.message(full_text)
            return Response(str(resp), mimetype="application/xml")

        # 2) 删除
        logger.info(f"[{req_id}] sync ids={list(parcel_list)}")
        success, failed, used_variant = [], [], {}
        for pid in parcel_list:
            ok, result = delete_parcel_with_variants_retry(pid)
            if ok:
                used = result.get("used", pid)
                success.append(pid)
                if used != pid:
                    used_variant[pid] = used
            else:
                failed.append(pid)
        logger.info(f"[{req_id}] sync result: deleted={len(success)} failed={len(failed)}")

        # 3) 组装【单条】回复文本：ACK + 明细
        lines = [ack_head, ""]
        lines.append(f"📦 Total {len(parcel_list)} | ✅ Deleted {len(success)} | ❌ Failed {len(failed)}")
        lines.append("")

        if stats:
            lines.append("📊 Recognition summary:")
            lines.append("\n".join(stats))
            lines.append("")

        if success:
            lines.append(f"✅ Deleted ({len(success)}):")
            show = success if len(success) <= 12 else success[:12] + [f"... and {len(success)-12} more"]
            for pid in show:
                note = f" (used {used_variant[pid]})" if pid in used_variant else ""
                lines.append(f"  • {pid}{note}")

        if failed:
            lines.append("")
            lines.append(f"❌ Failed ({len(failed)}):")
            showf = failed if len(failed) <= 8 else failed[:8] + [f"... and {len(failed)-8} more"]
            for pid in showf:
                lines.append(f"  • {pid}")

        full_text = "\n".join(lines)

        # 4) 返回【一条】Message（很关键）
        resp = MessagingResponse()
        resp.message(full_text)
        return Response(str(resp), mimetype="application/xml")

    except Exception as e:
        logger.error(f"[{req_id}] sync fatal: {repr(e)}", exc_info=True)
        resp = MessagingResponse()
        resp.message("⚠️ System error. Please try again later.")
        return Response(str(resp), mimetype="application/xml")
