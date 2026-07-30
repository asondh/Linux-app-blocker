package com.appblocker.monitor

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent

/**
 * The capture engine. For known browser packages it reads the address bar to
 * record the domain, and watches typed text to catch search terms, then buffers
 * visits and periodically uploads them to the dashboard.
 *
 * NOTE: address-bar view IDs differ by browser/version. If a browser records
 * nothing, add its `id/url_bar` equivalent to URL_BAR_IDS below (find it with
 * `uiautomatorviewer` or Layout Inspector on the device).
 */
class MonitorAccessibilityService : AccessibilityService() {

    private val URL_BAR_IDS = mapOf(
        "com.android.chrome" to "com.android.chrome:id/url_bar",
        "com.chrome.beta" to "com.chrome.beta:id/url_bar",
        "com.chrome.dev" to "com.chrome.dev:id/url_bar",
        "com.brave.browser" to "com.brave.browser:id/url_bar",
        "com.microsoft.emmx" to "com.microsoft.emmx:id/url_bar",
        "org.mozilla.firefox" to "org.mozilla.firefox:id/mozac_browser_toolbar_url_view",
        "com.opera.browser" to "com.opera.browser:id/url_field",
        "com.sec.android.app.sbrowser" to "com.sec.android.app.sbrowser:id/location_bar_edit_text",
        "com.duckduckgo.mobile.android" to "com.duckduckgo.mobile.android:id/omnibarTextInput"
    )

    private lateinit var store: Store
    private lateinit var cfg: Config
    private val handler = Handler(Looper.getMainLooper())
    private var lastRecorded = ""
    private var pendingQuery = ""
    private var pendingQueryAt = 0L

    override fun onServiceConnected() {
        store = Store(this)
        cfg = Config(this)
        Watchdog.ensureScheduled(this)
        handler.removeCallbacksAndMessages(null)   // don't stack loops on re-enable
        scheduleUpload()
    }

    override fun onUnbind(intent: Intent?): Boolean {
        // Service disabled: stop the periodic upload loop so it doesn't keep
        // running (and referencing this dead instance) after disconnect.
        handler.removeCallbacksAndMessages(null)
        return super.onUnbind(intent)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        val e = event ?: return
        val pkg = e.packageName?.toString() ?: return
        val urlBarId = URL_BAR_IDS[pkg] ?: return

        // Typed text in the omnibox is often the search query before navigation.
        if (e.eventType == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
            if (e.source?.viewIdResourceName == urlBarId) {
                val typed = e.text?.joinToString("")?.trim().orEmpty()
                if (typed.isNotBlank() && !Extract.looksLikeUrl(typed)) {
                    pendingQuery = typed
                    pendingQueryAt = System.currentTimeMillis()
                }
            }
            return
        }

        val root = rootInActiveWindow ?: return
        val text = try {
            root.findAccessibilityNodeInfosByViewId(urlBarId)
                ?.firstOrNull { !it.text.isNullOrBlank() }?.text?.toString()
        } catch (ex: Exception) {
            null
        } ?: return
        handleUrlBar(text)
    }

    private fun handleUrlBar(text: String) {
        val domain = Extract.domainOf(text)
        if (domain.isEmpty()) return
        // Only record when the visible target actually changed.
        val key = "$domain|$text"
        if (key == lastRecorded) return
        lastRecorded = key

        val user = cfg.childName
        if (user.isBlank()) return

        // Prefer a query embedded in the URL; else a recently-typed omnibox query
        // on a search domain.
        var q = Extract.extractSearchQuery(text)
        if (q.isBlank() && isSearchDomain(domain) &&
            System.currentTimeMillis() - pendingQueryAt < 20_000
        ) {
            q = pendingQuery
        }
        store.addVisit(Visit(user, domain, text, System.currentTimeMillis(), q))
    }

    private fun isSearchDomain(d: String) =
        d.contains("google") || d.contains("bing") || d.contains("duckduckgo") ||
        d.contains("yahoo") || d.contains("youtube") || d.contains("ecosia")

    private fun scheduleUpload() {
        handler.postDelayed({
            uploadNow()
            scheduleUpload()
        }, 60_000L)
    }

    private fun uploadNow() {
        if (!::cfg.isInitialized || !cfg.isConfigured) return
        Thread {
            try {
                Uploader.push(applicationContext)
            } catch (e: Exception) { /* retry on the next tick */ }
        }.start()
    }

    override fun onInterrupt() {}
}
