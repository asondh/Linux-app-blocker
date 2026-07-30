# AppBlocker Android monitor (phones & tablets)

A sideload-only companion to the Linux AppBlocker. It captures, per child device:

- **Domains visited** and **time per site** (from the browser address bar)
- **Search terms** (from search URLs and search boxes)
- **Full URLs** (best-effort, when the browser exposes them)
- **Screen time** per day (via Android UsageStats)

…then **pushes the data to the same private GitHub dashboard repo** as a file
`machines/<device-id>.json`, using the exact schema the Linux app uses. So the
phone shows up in your existing dashboard next to your computers — visits,
searches, and screen time included. No dashboard changes needed.

> This is an **iteration-1 scaffold**. It was written without an Android build
> environment, so treat it as a strong starting point to import into Android
> Studio and refine on-device — especially the browser address-bar view IDs in
> `MonitorAccessibilityService.kt`, which vary by browser/version.

## How it captures (and the honest limits)

- The core engine is an **AccessibilityService** — the one mechanism that can
  see domains + search terms + URLs across browsers without a VPN (so HTTPS/DoH
  don't blind it). It reads the browser's address bar and on-page search boxes.
- Because it's **sideloaded**, Play Store restrictions on Accessibility apps
  don't apply.
- A **persistent notification** is unavoidable for a reliable background
  service on modern Android — a savvy child can see it and could turn the
  service off in Settings. This raises the bar; it isn't invisible.

## Build & install (wireless debugging)

1. Open the `android/` folder in **Android Studio** (it's a standard Gradle
   project). It will generate the Gradle **wrapper** (`gradlew`) on first sync —
   that binary isn't committed here. Let it sync; align the AGP/Kotlin/SDK
   versions with your installed ones if it complains (see `build.gradle` files).
2. Connect the device over **wireless debugging** (`adb pair` / `adb connect`).
3. `Run` the app, or `./gradlew installDebug`.

## One-time setup on each device

Open the app and:

1. Enter the **child's name**, your **dashboard repo** (`owner/name`), a
   **GitHub token** with repo access, and branch (default `main`).
2. Tap **Enable Accessibility** → turn on "AppBlocker monitor" in the list.
3. Tap **Grant Usage Access** → allow it for the app.
4. Tap **Ignore battery optimization** → allow.
5. Tap **Test upload** — confirm the device appears in your dashboard.

## Files

- `MonitorAccessibilityService.kt` — capture engine (URL bar + search text →
  domain / query / time-per-site).
- `UsageCollector.kt` — per-day screen time via `UsageStatsManager`.
- `Store.kt` — on-device buffer of visits + today's screen seconds.
- `Uploader.kt` — builds `machines/<id>.json` and PUTs it to GitHub.
- `Extract.kt` — `domainOf` / `extractSearchQuery` (mirrors the Python).
- `MainActivity.kt` — setup screen + permission shortcuts.
