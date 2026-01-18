# JarSentry
JarRATScanner is a heuristic-based analysis tool designed to help users assess potential risk indicators in Minecraft .jar mods.  It focuses on static inspection, reputation checks, and common Remote Access Trojan (RAT) indicators — it is not an antivirus and does not execute or detonate files.

✨ Features
🔍 JAR Security Analysis

Scans Java JAR files for suspicious behavioral indicators

Uses a weighted risk scoring system with clear severity levels:

Low Risk

Medium Risk

High Risk

Designed to reduce false positives on legitimate mods and libraries


🛡️ Trust & Whitelisting

Built-in trust model for Forge and Fabric mods

Recognizes widely-used, legitimate mod distributions

Whitelisting support to prevent trusted mods from being flagged

🧠 Behavioral Heuristics

Detects potentially risky patterns such as:

Runtime string decryption

Heavy obfuscation

Network-related behavior indicators

Provides per-class behavior summaries instead of raw bytecode output

📊 Clear, User-Friendly Results

Displays a simple risk score (1–10) with color-coded warnings

Hides low-level technical strings from end users

Focuses on what the risk means, not raw implementation details

📦 File Selection Workflow

Scan JAR files via standard file picker

Automatic scan on file selection

No system-wide or background scanning

🎨 Modern Desktop Interface

Clean, dark-themed UI designed for readability

Minimal, distraction-free layout

Desktop-only (no background services or system hooks)

🔄 Extensible Detection System

Detection logic designed to be easily updated

Supports future integration of external threat intelligence feeds

Modular scoring system for tuning thresholds over time

🔐 Privacy-First Design

All analysis runs locally

No automatic file uploads

No telemetry or tracking

🧩 Intended Use

JarSentry is intended for:

Mod developers

Server administrators

Players verifying third-party mods

Security-conscious users analyzing untrusted JAR files

It is not an antivirus replacement and does not execute scanned files.

Always verify files using multiple trusted security sources.
