# Desktop application

This directory is reserved for the future Tauri 2 desktop application. Tauri,
React, TypeScript, Vite, and pnpm will be initialized during the desktop
integration milestone, when their configuration and generated files can be
reviewed as one coherent change.

The desktop Rust boundary will depend on `local-transfer-core`. The core must
not depend on Tauri or frontend code.
