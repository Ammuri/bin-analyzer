## README.MD

# C++ Static Binary Analyzer

A **static binary analysis** tool for ELF (Linux) and PE (Windows) executables, implemented in C++.

### 📋 Features I'm working on...

- **ELF & PE Header Parsing**: Inspect magic numbers, entry points, section tables.
- **String Extraction**: Pull printable ASCII/UTF‑8 strings.
- **Import/Export Analysis**: List imported functions (e.g., `VirtualAlloc`, `mmap`).
- **JSON Reporting**: Export findings in structured JSON for integration.

### ⚙️ Requirements

- **Compiler**: C++20 (cause I use std::span) compatible (GCC, Clang, MSVC)
- **Build System**: //TODO
- **Libraries**: (so far)
  - [nlohmann/json](https://github.com/nlohmann/json) (JSON serialization)


### 🔮 Roadmap

1. Entropy-based anomaly detection
2. Section-level analysis (e.g., `.text`, `.rodata`)


