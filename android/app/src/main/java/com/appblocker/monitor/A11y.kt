package com.appblocker.monitor

import android.content.ComponentName
import android.content.Context
import android.provider.Settings
import android.text.TextUtils

/** Whether THIS app's accessibility service is currently enabled by the user.
 *  Read from Settings.Secure so it's correct even from the watchdog worker,
 *  which runs when the service itself is off. */
object A11y {
    fun isEnabled(ctx: Context): Boolean {
        val setting = Settings.Secure.getString(
            ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false
        val myPkg = ctx.packageName
        val myClass = MonitorAccessibilityService::class.java.name
        val splitter = TextUtils.SimpleStringSplitter(':')
        splitter.setString(setting)
        while (splitter.hasNext()) {
            val comp = ComponentName.unflattenFromString(splitter.next())
            if (comp != null && comp.packageName == myPkg && comp.className == myClass) {
                return true
            }
        }
        return false
    }
}
