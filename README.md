# Windows Sandbox Init Script

## What it does

This project aims to automatically configure a Windows Sanbox for malware analysis with offline software packages.

## How to use

Make sure you have Windows Sandbox enabled.

Customize `packages.json` if you need to remove or add packages.

1. Run `download_pkgs.ps1` to download all packages for offline use, and update the checksums for later verification.
2. Start `start.wsb`.
3. Generally it should be done in 2 minutes.
4. Put malware samples in `./MALWARE` and you will find it on desktop.
5. Try with the provided sample, password is `infected` (from VX Underground).

Note:

1. Use `start.wsb` whenever possible
2. If Internet is needed, use `danger_zone_start_with_internet.wsb`, ideally in an isolated physical network
3. If you just need to capture some network traffic without the need of Internet connectivity, the default `start.wsb` should be sufficient, just capture traffic on the TUN device

## Screenshots

<https://github.com/user-attachments/assets/f9ba4652-7dab-4d32-a855-526733dbb473>

![tools](./screenshots/tools.png)
