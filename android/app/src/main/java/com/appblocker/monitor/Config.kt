package com.appblocker.monitor

import android.content.Context
import android.os.Build

/** Simple SharedPreferences-backed settings + a stable per-device id. */
class Config(ctx: Context) {
    private val sp = ctx.applicationContext
        .getSharedPreferences("appblocker", Context.MODE_PRIVATE)

    var childName: String
        get() = sp.getString("child", "") ?: ""
        set(v) = sp.edit().putString("child", v.trim()).apply()

    /** owner/name of the private dashboard repo. */
    var repo: String
        get() = sp.getString("repo", "") ?: ""
        set(v) = sp.edit().putString("repo", v.trim()).apply()

    var token: String
        get() = sp.getString("token", "") ?: ""
        set(v) = sp.edit().putString("token", v.trim()).apply()

    var branch: String
        get() = (sp.getString("branch", "main") ?: "main").ifBlank { "main" }
        set(v) = sp.edit().putString("branch", v.trim()).apply()

    val isConfigured: Boolean
        get() = repo.contains("/") && token.isNotBlank() && childName.isNotBlank()

    /** URL-safe device id → dashboard file machines/<deviceId>.json */
    val deviceId: String
        get() {
            sp.getString("device_id", null)?.let { return it }
            val raw = (childName.ifBlank { "phone" } + "-" + Build.MODEL)
                .lowercase()
                .replace(Regex("[^a-z0-9._-]"), "-")
                .trim('-', '.', '_')
            val id = raw.ifBlank { "android" }
            sp.edit().putString("device_id", id).apply()
            return id
        }

    /** Human-friendly machine name shown in the dashboard. */
    val machineName: String
        get() = (childName.ifBlank { "Android" } + "'s " + Build.MODEL)
}
