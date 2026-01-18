# JarSentry
JarRATScanner is a heuristic-based analysis tool designed to help users assess potential risk indicators in Minecraft .jar mods.  It focuses on static inspection, reputation checks, and common Remote Access Trojan (RAT) indicators — it is not an antivirus and does not execute or detonate files.

✨ Features

📦 JAR structure analysis

🔍 Suspicious class & method pattern detection

🌐 External link inspection (Discord, MediaFire, etc.)

📛 Known malicious indicator matching (hashes, strings, domains)

🧠 Risk scoring (low / medium / high)

🎨 Clean, modern desktop UI

📁 Manual file selection (no drag & drop required)


❌ What This Tool Does NOT Do

❌ Does not execute files

❌ Does not guarantee malware detection

❌ Does not replace antivirus software

❌ Does not claim 100% accuracy

False positives and false negatives are possible.


🧪 How Detection Works (High Level)

JarRATScanner assigns a risk score based on:

Known suspicious bytecode patterns

Hardcoded IPs, tokens, webhooks

Obfuscation indicators

External hosting or chat platform references

Community-reported malicious markers

No single indicator marks a file as malicious — results are contextual.



⚠️ Disclaimer

This project is provided for educational and research purposes only.

The author makes no guarantees regarding detection accuracy and assumes no liability for decisions made using this tool.

Always verify files using multiple trusted security sources.
