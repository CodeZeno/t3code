# Windows background polling verification

T3 Code's recurring Windows process, resource, and listening-port probes use
Kernel32 and IP Helper APIs directly. They must not invoke PowerShell or WMI.
Process-resource sampling is active only while the Diagnostics settings panel
is mounted and the T3 Code window is visible and focused.

Configuration:

- `T3CODE_PROCESS_RESOURCE_MONITOR=false` disables process-resource sampling.
- `T3CODE_PROCESS_RESOURCE_SAMPLE_INTERVAL_MS` sets its interval (default 15000 ms, minimum 1000 ms).
- `T3CODE_TERMINAL_PROCESS_POLL_INTERVAL_MS` sets terminal child-process inspection (default 2000 ms, minimum 500 ms).
- `T3CODE_PREVIEW_PORT_POLL_INTERVAL_MS` sets preview port discovery (default 5000 ms, minimum 1000 ms).

Manual Windows regression check:

1. Start T3 Code, open Diagnostics, then switch away from the window and back.
2. In Process Monitor, filter to children of `apps/server/dist/bin.mjs` and verify there are no recurring `powershell.exe` or `conhost.exe` processes.
3. In Task Manager, verify `WmiPrvSE.exe` stays near idle during normal use.
4. In Event Viewer, check `Microsoft-Windows-WMI-Activity/Operational` and verify T3 Code produces no recurring event 5858 `ExecQuery` failures.
5. Confirm Diagnostics still reports server/child CPU and resident memory, terminal activity labels update, and local preview listeners are detected.
