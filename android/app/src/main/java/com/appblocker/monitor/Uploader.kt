package com.appblocker.monitor

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Builds a machines/<device-id>.json payload in the SAME shape the Linux
 * AppBlocker publishes (build_report_data) and PUTs it to the dashboard repo,
 * so the phone shows up as another device. Call from a background thread.
 */
object Uploader {

    fun push(ctx: Context): Int {
        val cfg = Config(ctx)
        require(cfg.isConfigured) { "Set child name, repo (owner/name) and token first." }
        val payload = buildPayload(ctx, cfg).toString().toByteArray(Charsets.UTF_8)
        val path = "machines/${cfg.deviceId}.json"
        val base = "https://api.github.com/repos/${cfg.repo}/contents/$path"

        val sha = getSha("$base?ref=${cfg.branch}", cfg.token)
        val body = JSONObject()
            .put("message", "Android activity ${nowStr()}")
            .put("content", Base64.encodeToString(payload, Base64.NO_WRAP))
            .put("branch", cfg.branch)
        if (sha != null) body.put("sha", sha)

        put(base, cfg.token, body.toString())
        return payload.size
    }

    private fun buildPayload(ctx: Context, cfg: Config): JSONObject {
        val nowSec = System.currentTimeMillis() / 1000
        val user = cfg.childName
        val visits = JSONArray()
        for (v in Store(ctx).snapshot()) {
            visits.put(
                JSONObject().put("u", v.u).put("d", v.d).put("url", v.url)
                    .put("ts", v.ts / 1000).put("q", v.q)
            )
        }
        val screenTime = JSONObject().put(user, UsageCollector.screenSecondsToday(ctx))
        return JSONObject()
            .put("generated_at", nowSec)
            .put("generated_at_str", nowStr())
            .put("machine", cfg.machineName)
            .put("machine_id", cfg.deviceId)
            .put("days", 7)
            .put("truncated", false)
            .put("users", JSONArray().put(user))
            .put("visits", visits)
            .put("attempts", JSONArray())
            .put("new_domains", JSONArray())
            .put("screen_time", screenTime)
            .put("screen_day", UsageCollector.today())
    }

    private fun getSha(url: String, token: String): String? {
        val c = open(url, token, "GET")
        return try {
            if (c.responseCode == 404) return null
            if (c.responseCode !in 200..299) throw RuntimeException(
                "GitHub GET ${c.responseCode}: ${errorText(c)}"
            )
            val json = JSONObject(c.inputStream.bufferedReader().readText())
            json.optString("sha").ifBlank { null }
        } finally {
            c.disconnect()
        }
    }

    private fun put(url: String, token: String, body: String) {
        val c = open(url, token, "PUT")
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json")
        try {
            c.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            if (c.responseCode !in 200..299) throw RuntimeException(
                "GitHub PUT ${c.responseCode}: ${errorText(c)}"
            )
            c.inputStream.bufferedReader().readText()
        } finally {
            c.disconnect()
        }
    }

    private fun open(url: String, token: String, method: String): HttpURLConnection {
        val c = URL(url).openConnection() as HttpURLConnection
        c.requestMethod = method
        c.connectTimeout = 30000
        c.readTimeout = 30000
        c.setRequestProperty("Authorization", "Bearer $token")
        c.setRequestProperty("Accept", "application/vnd.github+json")
        c.setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
        c.setRequestProperty("User-Agent", "AppBlockerMonitor")
        return c
    }

    private fun errorText(c: HttpURLConnection): String =
        try { (c.errorStream ?: c.inputStream).bufferedReader().readText() }
        catch (e: Exception) { "" }

    private fun nowStr(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())
}
