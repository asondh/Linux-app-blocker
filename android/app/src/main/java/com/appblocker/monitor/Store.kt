package com.appblocker.monitor

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** A visit record matching the dashboard schema: user, domain, url, ts, query. */
data class Visit(
    val u: String, val d: String, val url: String, val ts: Long, val q: String
)

/**
 * File-backed buffer of recent visits. Deliberately small and simple: appends
 * de-duplicated visits, caps the list, and keeps ~7 days so the dashboard's
 * "today" and recent views have data even across reboots.
 */
class Store(ctx: Context) {
    private val file = File(ctx.applicationContext.filesDir, "visits.json")
    private val max = 5000
    private val keepMs = 7L * 86400_000L

    // One process-wide lock: several Store instances (service writer, uploader
    // reader) share the same file, so the lock must be shared too — a per-
    // instance lock would let them corrupt visits.json concurrently.
    private companion object {
        val LOCK = Any()
    }

    fun addVisit(v: Visit) {
        synchronized(LOCK) {
            val list = readList()
            // Skip an immediate duplicate (same domain+query as the last entry).
            val last = list.lastOrNull()
            if (last != null && last.d == v.d && last.q == v.q &&
                v.ts - last.ts < 15_000
            ) return
            list.add(v)
            val cutoff = v.ts - keepMs
            val trimmed = list.filter { it.ts >= cutoff }.takeLast(max)
            writeList(trimmed)
        }
    }

    fun snapshot(): List<Visit> = synchronized(LOCK) { readList() }

    private fun readList(): MutableList<Visit> {
        if (!file.exists()) return mutableListOf()
        return try {
            val arr = JSONArray(file.readText())
            MutableList(arr.length()) { i ->
                val o = arr.getJSONObject(i)
                Visit(
                    o.optString("u"), o.optString("d"), o.optString("url"),
                    o.optLong("ts"), o.optString("q")
                )
            }
        } catch (e: Exception) {
            mutableListOf()
        }
    }

    private fun writeList(list: List<Visit>) {
        val arr = JSONArray()
        for (v in list) {
            arr.put(
                JSONObject()
                    .put("u", v.u).put("d", v.d).put("url", v.url)
                    .put("ts", v.ts).put("q", v.q)
            )
        }
        try {
            file.writeText(arr.toString())
        } catch (e: Exception) { /* best-effort */ }
    }
}
