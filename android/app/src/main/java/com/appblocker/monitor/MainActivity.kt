package com.appblocker.monitor

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

/** Setup screen: enter dashboard credentials + shortcuts to grant permissions
 *  and run a test upload. */
class MainActivity : AppCompatActivity() {

    private lateinit var cfg: Config

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        cfg = Config(this)
        Watchdog.ensureScheduled(this)

        val child = findViewById<EditText>(R.id.child)
        val repo = findViewById<EditText>(R.id.repo)
        val token = findViewById<EditText>(R.id.token)
        val branch = findViewById<EditText>(R.id.branch)
        val status = findViewById<TextView>(R.id.status)

        child.setText(cfg.childName)
        repo.setText(cfg.repo)
        token.setText(cfg.token)
        branch.setText(cfg.branch)

        findViewById<Button>(R.id.save).setOnClickListener {
            cfg.childName = child.text.toString()
            cfg.repo = repo.text.toString()
            cfg.token = token.text.toString()
            cfg.branch = branch.text.toString()
            Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
            refresh(status)
        }
        findViewById<Button>(R.id.enableA11y).setOnClickListener {
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }
        findViewById<Button>(R.id.usage).setOnClickListener {
            startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
        }
        findViewById<Button>(R.id.battery).setOnClickListener {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        Uri.parse("package:$packageName")
                    )
                )
            } catch (e: Exception) {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            }
        }
        findViewById<Button>(R.id.test).setOnClickListener {
            status.text = "Uploading…"
            Thread {
                val msg = try {
                    val n = Uploader.push(applicationContext)
                    "✓ Uploaded $n bytes to machines/${cfg.deviceId}.json"
                } catch (e: Exception) {
                    "✗ ${e.message}"
                }
                runOnUiThread { status.text = msg }
            }.start()
        }
    }

    override fun onResume() {
        super.onResume()
        refresh(findViewById(R.id.status))
    }

    private fun refresh(status: TextView) {
        val usage = if (UsageCollector.hasUsageAccess(this)) "granted" else "NOT granted"
        status.text = buildString {
            append("Device id: ${cfg.deviceId}\n")
            append("Configured: ${if (cfg.isConfigured) "yes" else "no — fill in fields"}\n")
            append("Usage access: $usage\n")
            append("Screen time today: ${UsageCollector.screenSecondsToday(this@MainActivity) / 60} min\n")
            append("Enable Accessibility in Settings if not already on.")
        }
    }
}
