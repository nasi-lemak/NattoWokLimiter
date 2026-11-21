# Testing on Windows (about 15 minutes)

CI builds and tests the Windows version on a Windows server (unit tests, the service, the installer),
but nobody has used it on a real Windows desktop yet. This checklist covers what CI can't: what the
app looks like and does on a real PC. Note what happens at each step; screenshots of anything odd
help a lot.

Windows 10 or 11, an account with Administrator rights.

## 1. Install (2 min)

1. Get `nattowok-setup-x86_64.exe` (from the `windows-x86_64` CI artifact or a release).
2. Run it. Windows SmartScreen may warn because the installer isn't signed yet: **More info → Run
   anyway**.
3. Finish the installer with **Open NattoWok Limiter** ticked.

**Expected:** the app opens; the header says **Enforcing** (green). Services (`services.msc`) lists
**NattoWok Limiter** as Running, startup type Automatic.

## 2. Seeing traffic (3 min)

1. Open a browser and play a video; start a download in another app.
2. Look at the Applications tab.

**Expected:** your browser and the other app appear with their **real names and icons** (e.g.
"Firefox" with the Firefox logo), with download speeds that roughly match what Task Manager shows.
Connections lists their connections.

*Note:* Applications show TCP traffic per app; UDP traffic (some games, video calls, QUIC in
browsers) is counted in the totals but not per app on Windows yet.

## 3. Blocking (2 min)

1. Applications → **Block** next to your browser.
2. Try loading a website.
3. Click **Blocked** to unblock, and load it again.

**Expected:** the site fails to load while blocked, and works again after unblocking. In
`wf.msc` (Windows Defender Firewall → Outbound rules) rules named `NattoWokLimiter …` appear while
blocked and disappear after.

## 4. Upload limit (2 min)

1. **Limit…** on an app that uploads (a cloud sync app, or upload a large file in a browser), upload
   `200kB/s`.
2. Watch its upload speed.

**Expected:** its upload settles near 200 kB/s. (Download limits aren't supported on Windows; the
app says so.)

## 5. Metered network (2 min)

1. Settings → Network & Internet → your connection → turn on **Metered connection**.
2. Within a few seconds the header's network chip should say **· metered**.
3. Rules → Presets… → **Hotspot saver** → Add; if you have Steam, OneDrive or Dropbox running,
   they're blocked now.
4. Turn metered off again; they're unblocked.

## 6. Tray, notifications, start with login (2 min)

1. Close the window: it should stay in the tray (bottom right), with the speed shown in the icon.
2. Right-click the tray icon: the menu lists busy apps with Block and Limit options.
3. ⚙ → **Send a test notification**: a Windows notification appears.
4. ⚙ → tick **Start NattoWok Limiter when I log in**; sign out and in: it starts in the tray.

## 7. Uninstall (1 min)

Settings → Apps → NattoWok Limiter → Uninstall.

**Expected:** the service is gone from Services, the `NattoWokLimiter` firewall rules are gone, and
`C:\Program Files\NattoWok Limiter` is removed. (Your rules stay in
`C:\ProgramData\NattoWokLimiter`, so a reinstall keeps them; delete that folder to remove them.)

## What to send back

For each step: worked / didn't (and what you saw). If something failed, add
`C:\ProgramData\NattoWokLimiter\nwld.log` and the output of
`"C:\Program Files\NattoWok Limiter\nwl.exe" status` from a Command Prompt.
