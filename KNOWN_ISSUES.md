# Known Issues

## Right-click context menus not working (under investigation)

**Affected:** Column headers, data rows, and data cells  
**Branch:** `feature/custom-enhancements`  
**Status:** Investigation in progress

### Symptom
Right-clicking on column headers or data rows/cells does nothing. `⌘+Click` / `Ctrl+Click` works correctly and opens the expected context menu.

### What was tried
1. Removed `e.preventDefault()` from the `mousedown` capture handler for `button=2` — on macOS/Chromium, calling `preventDefault` on `mousedown` with button=2 can suppress the subsequent `contextmenu` DOM event. Fix is committed but menus still do not appear.
2. Added `e.stopPropagation()` to the row container's `onContextMenu` handler to prevent event bubbling from interfering.

### Current diagnostic finding
Temporary `console.log` tracing showed **no logs at all** when right-clicking, meaning none of the three expected paths fire:
- `document.addEventListener("mousedown", handler, true)` — capture-phase handler
- React `onContextMenu` on column header / row div elements  
- IPC path: Electron `webContents.on("context-menu")` → `safeSend("native-context-menu")` → renderer

### Next steps to investigate
- Determine whether macOS trackpad two-finger tap only emits `contextmenu` (no `mousedown` button=2) — if so the capture handler would never see it
- Check whether `event.preventDefault()` in the main-process `context-menu` handler suppresses the renderer-side `contextmenu` DOM event
- Check for transparent overlay elements sitting on top of the grid that might swallow pointer events before they reach column headers or row divs

### Relevant files
| File | Location |
|------|----------|
| `src/App.jsx` | `handleNativeRightClick` (~line 2076), mousedown handler (~line 2120), column header `onContextMenu` (~line 4204/4223), row `onContextMenu` (~line 4376) |
| `electron/main.js` | `webContents.on("context-menu")` handler (~line 280) |
| `electron/preload.js` | `onNativeContextMenu` IPC bridge (~line 124) |
