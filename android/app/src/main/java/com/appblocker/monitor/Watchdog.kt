package com.appblocker.monitor

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Runs independently of the AccessibilityService (every ~15 min, WorkManager's
 * minimum). It uploads current status — crucially including whether the
 * accessibility service is still enabled — so if a child turns monitoring off,
 * the device keeps reporting `accessibility_enabled = false` and the dashboard
 * flags it. If the app is force-stopped or uninstalled, uploads simply stop and
 * the dashboard shows the device as stale. WorkManager reschedules periodic work
 * across reboots on its own.
 */
class Watchdog(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
    // doWork() runs on a WorkManager background thread, so the blocking network
    // call in Uploader.push is fine here.
    override fun doWork(): Result {
        if (!Config(applicationContext).isConfigured) return Result.success()
        return try {
            Uploader.push(applicationContext)
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }

    companion object {
        private const val NAME = "appblocker-watchdog"

        /** Idempotent: schedule the periodic watchdog if not already scheduled. */
        fun ensureScheduled(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<Watchdog>(15, TimeUnit.MINUTES)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(
                NAME, ExistingPeriodicWorkPolicy.KEEP, req
            )
        }
    }
}
