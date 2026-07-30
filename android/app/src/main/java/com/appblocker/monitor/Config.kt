package com.appblocker.monitor

import android.content.Context
import android.os.Build
import android.provider.Settings

/** Simple SharedPreferences-backed settings + a stable per-device id. */
class Config(ctx: Context) {
    private val appCtx = ctx.applicationContext
    private val sp = appCtx.getSharedPreferences("appblocker", Context.MODE_PRIVATE)

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

    /** URL-safe device id → dashboard file machines/<deviceId>.json.
     *  Includes an ANDROID_ID suffix so two devices with the same child name +
     *  model can't write to the same file and clobber each other. Persisted once
     *  the child name is known so the readable name sticks. */
    val deviceId: String
        get() {
            sp.getString("device_id", null)?.let { return it }
            val aid = try {
                Settings.Secure.getString(
                    appCtx.contentResolver, Settings.Secure.ANDROID_ID
                )
            } catch (e: Exception) {
                null
            }
            val suffix = (aid ?: "").filter { it.isLetterOrDigit() }
                .takeLast(6).ifBlank { "device" }
            val base = (childName.ifBlank { "android" } + "-" + Build.MODEL + "-" + suffix)
                .lowercase()
                .replace(Regex("[^a-z0-9._-]"), "-")
                .trim('-', '.', '_')
            val id = base.ifBlank { "android-$suffix" }
            // Only persist once we have a real child name, so the id reads nicely.
            if (childName.isNotBlank()) sp.edit().putString("device_id", id).apply()
            return id
        }

    /** Human-friendly machine name shown in the dashboard. */
    val machineName: String
        get() = (childName.ifBlank { "Android" } + "'s " + Build.MODEL)
}
