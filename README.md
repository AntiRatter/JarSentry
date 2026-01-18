⭐ Key Features

Static security analysis for Java JAR files

Clear risk scoring (1–10) with Low / Medium / High severity levels

Trust model for Forge and Fabric mods to reduce false positives

Detection of suspicious patterns such as heavy obfuscation and runtime string decryption

Per-class behavior summaries (no raw bytecode exposed)

Local-only scanning — no file uploads, no telemetry

Simple desktop UI with automatic scan on file selection

🚀 Elevator Pitch

JarSentry is a lightweight desktop tool designed to help users assess the safety of Java JAR files before running them. It performs local, static analysis to identify suspicious behavioral indicators while minimizing false positives on legitimate mods and libraries. JarSentry presents results through a clear risk score and severity level, making it accessible to non-technical users while remaining useful to developers and security-conscious mod users.

⚠️ Limitations

JarSentry performs static analysis only and does not execute or sandbox scanned files. As a result, it may not detect threats that rely entirely on runtime behavior or external payload delivery. While care is taken to reduce false positives, no automated analysis tool can guarantee perfect accuracy. JarSentry should be used as a risk assessment aid, not as a replacement for professional malware analysis or endpoint protection software.
