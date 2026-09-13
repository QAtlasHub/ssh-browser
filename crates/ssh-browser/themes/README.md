# Themes

[base16] colour schemes, vendored from [tinted-theming/schemes] at `spec-0.11`, under the
MIT licence in `LICENSE`. Each file names its own author; that line is part of the file and
should stay there.

A curated set rather than all of them. The upstream repository carries several hundred, and
a list somebody scrolls past is not a choice — these are the ones a reader would recognise
by name, in light and dark pairs where the scheme has both.

## Adding one

Drop the `.yaml` in and add a line to `SCHEMES` in `../src/theme/mod.rs`. Nothing else: the
listing's stylesheet is written entirely against the custom properties built from these
sixteen colours, so a scheme is a palette and never a second copy of the layout.

`every_vendored_scheme_parses` will say so if the file is not what it claims to be.

## What the sixteen slots become

base16's own meanings, not a guess at which colour looks nice. `base00` is the background
and `base05` the foreground in every scheme, light or dark — a light scheme simply runs
`base00`..`base07` the other way — which is what lets one mapping serve both.

| slot | base16 means | used as |
| --- | --- | --- |
| `base00` | Default Background | page background |
| `base01` | Lighter Background | row hover, indent guides |
| `base02` | Selection Background | the selected row |
| `base03` | Comments, Invisibles | the faintest readable text |
| `base04` | Dark Foreground | dimmed text |
| `base05` | Default Foreground | text |
| `base09` | Constants, Markup | HTML files |
| `base0A` | Classes, Search | data files |
| `base0B` | Strings, Diff Inserted | images and media |
| `base0D` | Functions, Headings | accent, and documents |
| `base0E` | Keywords, Storage | source files |

[base16]: https://github.com/tinted-theming/home/blob/main/styling.md
[tinted-theming/schemes]: https://github.com/tinted-theming/schemes
