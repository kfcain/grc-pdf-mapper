# DESIGN.md

## Visual theme

Night audit desk. Pure near-black field, moss primary from seed hue 160°, amber only for obligation strength warnings. Restrained color strategy.

## Color (OKLCH)

| Token | Value | Role |
|---|---|---|
| `--bg` | `oklch(0.12 0 0)` | Page |
| `--surface` | `oklch(0.16 0.008 160)` | Panels / drop target |
| `--surface-2` | `oklch(0.20 0.01 160)` | Hover / elevated |
| `--ink` | `oklch(0.93 0.01 160)` | Primary text |
| `--muted` | `oklch(0.68 0.02 160)` | Secondary text |
| `--line` | `oklch(0.28 0.012 160)` | Hairlines |
| `--primary` | `oklch(0.72 0.12 160)` | Actions / focus |
| `--primary-ink` | `oklch(0.16 0.02 160)` | Text on primary |
| `--warn` | `oklch(0.78 0.12 75)` | Must / shall cues |
| `--danger` | `oklch(0.68 0.17 25)` | Errors / prohibited |
| `--ok` | `oklch(0.72 0.10 160)` | Success |

## Typography

- UI: IBM Plex Sans (400/500/600)
- Data / control ids: IBM Plex Mono (400/500)
- Fixed rem scale (~1.15): 12 / 14 / 16 / 18 / 22 / 28

## Layout

Max width ~1080px. Single column on mobile; on desktop, drop zone above a results stack (summary → tabs → table). No card grids. Borders and spacing define regions.

## Components

- Drop zone: full-bleed interaction surface with dashed border; solid on drag
- Primary button: moss fill, 6px radius
- Table: dense rows, mono control cells
- Tabs: underline selected state, not pills
- Toasts / inline errors under the drop zone

## Motion

150–220ms ease-out. Drag highlight, results crossfade, focus ring only. No page-load choreography.
