# Windows Sandbox Init Script

## What it does

This project aims to automatically configure a Windows Sanbox for malware analysis with offline software packages in current working directory.

## How to use

Make sure you have Windows Sandbox enabled.

1. Run `download_pkgs.ps1` to download all packages for offline use, and update the checksums for later verification.
2. Start `start.wsb`.
3. Generally it should be done within a minute.

Note:

1. Use `start.wsb` whenever possible
2. If Internet is needed, use `danger_zone_start_with_internet.wsb`, ideally in an isolated physicall network
3. If you just need to capture some network traffic without the need of Internet connectivity, the default `start.wsb` should be sufficient, just capture traffic on the TUN device

## Screenshots

<https://github.com/user-attachments/assets/f9ba4652-7dab-4d32-a855-526733dbb473>

![tools](./screenshots/tools.png)
