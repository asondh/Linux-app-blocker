package com.appblocker.monitor

import android.net.Uri

/** Mirrors the Python domain_of / extract_search_query so the dashboard sees
 *  the same shape of data from phones as from computers. */
object Extract {

    private val SEARCH_HOSTS = listOf(
        "google.", "bing.com", "duckduckgo.com", "search.yahoo", "yahoo.com",
        "ecosia.org", "startpage.com", "youtube.com", "youtube.", "brave.com"
    )
    // param name per engine that holds the query text
    private val QUERY_PARAMS = listOf("q", "query", "search_query", "p", "text")

    fun domainOf(rawUrl: String?): String {
        val host = hostOf(rawUrl) ?: return ""
        return host.removePrefix("www.").lowercase()
    }

    fun extractSearchQuery(rawUrl: String?): String {
        val uri = uriOf(rawUrl) ?: return ""
        val host = (uri.host ?: "").lowercase()
        if (SEARCH_HOSTS.none { host.contains(it) }) return ""
        for (p in QUERY_PARAMS) {
            val v = try { uri.getQueryParameter(p) } catch (e: Exception) { null }
            if (!v.isNullOrBlank()) return v.trim()
        }
        return ""
    }

    /** True when a string looks like a URL/host we can record. */
    fun looksLikeUrl(s: String?): Boolean {
        val t = s?.trim() ?: return false
        if (t.isEmpty() || t.contains(' ')) return false
        return t.contains('.') && (t.startsWith("http") || !t.contains('/') ||
                t.substringBefore('/').contains('.'))
    }

    private fun uriOf(rawUrl: String?): Uri? {
        var s = rawUrl?.trim() ?: return null
        if (s.isEmpty()) return null
        if (!s.contains("://")) s = "http://$s"
        return try { Uri.parse(s) } catch (e: Exception) { null }
    }

    private fun hostOf(rawUrl: String?): String? = uriOf(rawUrl)?.host?.takeIf { it.isNotBlank() }
}
