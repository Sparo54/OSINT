# OFT — Operation Find Them

A security multi-tool built with Electron: OSINT link hub, IP intelligence, DNS/domain tools, network diagnostics, port scanning, TLS/HTTP inspection, threat intelligence lookups, and terminal access — all in one black/white/red desktop dashboard.

![platform](https://img.shields.io/badge/platform-Windows-black) ![license](https://img.shields.io/badge/license-MIT-white)

## ⚠️ Legal Notice

This tool is provided strictly for lawful, authorized use — authorized security testing, OSINT research you have the legal right to conduct, educational study, and investigation of your own systems or accounts. **You are solely responsible** for ensuring your use complies with all applicable laws (including computer-crime, privacy, and anti-stalking laws) and that you have authorization before investigating, scanning, or querying any person, system, or network that is not your own.

Neither this tool nor its creator authorizes or condones unauthorized access, stalking, harassment, or any unlawful use. See the full Legal Notice and Copyright Notice inside the app (**About → Legal Notice**) for complete terms. This is provided as general information, not legal advice — if you plan to distribute or use this tool in a way that has real legal stakes, consult an actual lawyer.

## Features

- **OSINT Hub** — categorized links to breach, email, phone, image, people-search, and username-lookup services
- **IP Intelligence** — geolocation, ISP/ASN, proxy/hosting detection, reverse DNS
- **DNS & Domain Intelligence** — full record lookup, DNSSEC validation, WHOIS/RDAP
- **Network Diagnostics** — ping, traceroute, TCP connect, local interface info
- **Port Tester** — profile-based or custom-range TCP scanning with labeled, known services
- **Web & TLS Security** — certificate inspection, HTTP security headers, redirect chains
- **Threat Intelligence** — Tor exit-node check, public DNS blocklist lookups
- **Infrastructure Mapping** — subdomain discovery via certificate transparency
- **Terminal Access** — launch a local CMD window or open a cloud shell
- **Utilities** — subnet calculator, bulk IP lookup, searchable history, JSON/CSV/TXT export

## Requirements

- Windows 10/11
- [Node.js](https://nodejs.org) 18 or newer

## A note on antivirus warnings

This app is not code-signed. Windows SmartScreen or your antivirus may flag it on first run, especially because it performs port scanning and can launch a terminal — this is expected behavior for an unsigned tool with these capabilities, not an indication of malware. Review the source yourself; it's all here.

## Third-party services

Several tools call free public APIs with no key required (`ip-api.com`, `crt.sh`, `rdap.org`, `dns.google`, Spamhaus/Barracuda/SpamCop/DroneBL DNSBLs, the Tor Project's exit-node list). These have their own rate limits — heavy use may get temporarily throttled. Links in the OSINT Hub open third-party websites in your browser; OFT has no affiliation with any of them.

## License

MIT — see [LICENSE](LICENSE).

## Credits

Designed and developed by **Sparo**.
