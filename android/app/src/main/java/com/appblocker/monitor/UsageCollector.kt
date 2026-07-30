package com.appblocker.monitor

import android.app.AppOpsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.os.Build
import android.os.Process
import java.util.Calendar

/** Per-day screen-on time via UsageStats: sum of foreground time across apps
 *  since local midnight. Approximates "computer on" time for the dashboard. */
object UsageCollector {

    @Suppress("DEPRECATION")   // checkOpNoThrow: needed for the API 26-28 path
    fun hasUsageAccess(ctx: Context): Boolean {
        return try {
            val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            // unsafeCheckOpNoThrow is API 29+; fall back to checkOpNoThrow on 26-28.
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ops.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName
                )
            } else {
                ops.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName
                )
            }
            mode == AppOpsManager.MODE_ALLOWED
        } catch (e: Exception) {
            false
        }
    }

    /** Total foreground seconds today (all apps), capped at 24h. */
    fun screenSecondsToday(ctx: Context): Long {
        if (!hasUsageAccess(ctx)) return 0
        val usm = ctx.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val start = midnightMillis()
        val now = System.currentTimeMillis()
        val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, start, now)
            ?: return 0
        var totalMs = 0L
        for (s in stats) {
            if (s.lastTimeUsed >= start) totalMs += s.totalTimeInForeground
        }
        val secs = totalMs / 1000
        return secs.coerceIn(0, 86400)
    }

    fun today(): String {
        val c = Calendar.getInstance()
        return "%04d-%02d-%02d".format(
            c.get(Calendar.YEAR), c.get(Calendar.MONTH) + 1, c.get(Calendar.DAY_OF_MONTH)
        )
    }

    private fun midnightMillis(): Long {
        val c = Calendar.getInstance()
        c.set(Calendar.HOUR_OF_DAY, 0); c.set(Calendar.MINUTE, 0)
        c.set(Calendar.SECOND, 0); c.set(Calendar.MILLISECOND, 0)
        return c.timeInMillis
    }
}
