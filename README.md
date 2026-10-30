# J.A.R.V.I.S. Server AI

Asisten AI lokal (Ollama) untuk mengelola server STB Armbian.
- Model: `qwen2.5:0.5b` (ringan)
- Fitur: Router instan, Safety Gate, Self-Fix, dan eksekusi bash bebas.

## Instalasi
1. Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`
2. Pull model: `ollama pull qwen2.5:0.5b`
3. Copy `jarvis.py` ke `/usr/local/bin/jarvis` dan `chmod +x`.
4. Jalankan: `jarvis`
