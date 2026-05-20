# Signature-Base Integration

This backend now supports loading Signature-Base IOC files from a local `signatures/iocs/` folder.

## How it works

- `app.py` always loads `signatures/known_signatures.json`.
- It also loads any `*.txt` files from `signatures/iocs/`.
- Supported IOC file types:
  - `c2-iocs.txt`
  - `filename-iocs.txt`
  - `hash-iocs.txt`
  - `keywords.txt`

## Populate the IOC files

You can download the sample Signature-Base IOC files using:

```bash
cd d:\shieldGuard\fastapi-backend
python download_signature_base.py
```

Or clone the repository and copy the `iocs/` files under `signatures/iocs/`.

## After adding files

Restart the backend so it can reload the new IOC entries.

## Verification

If you want to verify the loaded signature count, you can add a quick log or query the app after startup.
