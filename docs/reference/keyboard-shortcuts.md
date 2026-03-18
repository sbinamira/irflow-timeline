---
description: Keyboard shortcuts reference for IRFlow Timeline — file operations, navigation, search, and analysis commands.
---

# Keyboard Shortcuts

## File Operations

| Shortcut | Action |
|----------|--------|
| `Cmd+O` | Open file |
| `Cmd+E` | Export filtered data |
| `Cmd+S` | Save session |
| `Cmd+Shift+O` | Load session |
| `Cmd+Shift+R` | Generate report |

## Navigation

| Shortcut | Action |
|----------|--------|
| `Cmd+W` | Close active tab |
| `Cmd+Shift+Q` | Close all tabs |
| `Cmd+1-9` | Switch to tab 1-9 |
| `Cmd+Tab` | Next tab |
| `Cmd+Shift+Tab` | Previous tab |
| `Up / Down` | Navigate rows |

## Search & Filter

| Shortcut | Action |
|----------|--------|
| `Cmd+F` | Focus search bar |
| `Cmd+Shift+F` | Cross-tab search (Cross Find) |
| `F3` / `Cmd+Right` | Next search match |
| `Shift+F3` / `Cmd+Left` | Previous search match |
| `Cmd+B` | Toggle bookmarked rows only |
| `Escape` | Clear search / close modal / close panel |

## Grid

| Shortcut | Action |
|----------|--------|
| `Cmd+Shift+C` | Column Manager |
| `Cmd+Shift+L` | Conditional Formatting |
| `Cmd+R` | Reset column widths |
| `Cmd+Plus` / `Cmd+Minus` | Increase / decrease font size |
| `Click` | Select row |
| `Shift+Click` | Range select rows |
| `Cmd+Click` / `Ctrl+Click` cell | Cell quick actions (Filter in / Filter out / Hide column) |
| `Right-click` cell | Full context menu (Copy, Filter, Tags, VT lookup) |
| `Shift+F10` | Context menu (keyboard) |
| `Double-click` | Cell detail popup |
| `Double-click border` | Auto-fit column width |
| `Drag header` | Group by column |

## Selection

| Shortcut | Action |
|----------|--------|
| `Cmd+C` | Copy selected rows |
| Select All | Select all rows (Actions menu) |
| Deselect All | Clear selection (Actions menu) |
| Invert Selection | Toggle selection state (Actions menu) |

## Tools

| Shortcut | Action |
|----------|--------|
| `Cmd+H` | Toggle histogram |

## General

| Shortcut | Action |
|----------|--------|
| `Cmd+,` | Preferences |
| `Cmd+Q` | Quit |
| `Cmd+M` | Minimize window |
| `Cmd+Shift+F` | Toggle fullscreen |

## Search Syntax

| Pattern | Meaning |
|---------|---------|
| `word1 word2` | OR (matches either) |
| `+word` | AND (must include) |
| `-word` | EXCLUDE |
| `"exact phrase"` | Phrase match |
| `Column:value` | Column-specific filter |
| `FL` / `HL` | Toggle filter / highlight mode |

## Context Menu Shortcuts

**`Cmd+Click` any cell** opens a quick-action menu:

- Filter in (show only matching rows)
- Filter out (exclude matching rows)
- Hide column

**Right-click any cell** opens the full context menu:

- Copy cell / Copy row
- Filter in / Filter out
- Tags ▸ (hover submenu — supports multi-row tagging)
- VirusTotal lookup (for IPs, hashes, domains)

**Right-click any column header** for column actions:

- Pin / Unpin column
- Group by column
- Sort ascending / descending
- Stack values
- Column stats
- Auto-fit column width
- Create color rule
- Hide column
