WHITELIST GUARD — SINGLE-EXE WINDOWS PROJECT
============================================

INTENDED RESULT
- One self-contained WhitelistGuard.exe for Windows 10/11 x64.
- GUI supports adding/removing domains and importing/exporting TXT.
- "Install protection" requests Administrator rights, copies itself to Program Files,
  creates a startup Scheduled Task, sets active adapters' DNS to 127.0.0.1,
  blocks conventional outbound DNS (53) and DNS-over-TLS (853), and disables built-in
  DNS-over-HTTPS in Chrome and Edge through machine policies.
- The background DNS engine only resolves domains present in allowed-sites.txt.
- The GUI and background DNS service are the same executable with different modes.

BUILD THE EXE
This package contains source, not a precompiled EXE. To build:
Option A: Push this folder to a GitHub repository, then Actions > Build single-file Windows EXE
> Run workflow. Download the WhitelistGuard-Windows-x64 artifact.
Option B: On a Windows build PC with .NET 8 SDK installed, run:
  dotnet publish WhitelistGuard.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true

DEPLOY
1. Copy only WhitelistGuard.exe to the target Windows PC.
2. Run it.
3. Click Import TXT or add domains manually.
4. Click Install protection and approve the UAC prompt.
5. Restart Windows and test on ONE non-critical PC first.
6. Reopen WhitelistGuard.exe to change the allowlist.

TXT FORMAT
One domain per line:
example.com
company.com
portal.company.com
Lines starting with # are ignored. Allowing a domain also allows its subdomains.

IMPORTANT LIMITATIONS / SAFETY
- This is DNS-layer enforcement for traffic using the Windows DNS resolver. It is not a
  complete web firewall and does NOT guarantee blocking every browser or application.
- Chrome and Edge built-in DoH are disabled by policy; Firefox, Brave, Opera, Tor, VPNs,
  proxies, third-party encrypted DNS, direct-IP connections, and apps using hard-coded IPs
  may bypass. Use managed endpoint policies and a secure web gateway for stronger control.
- When the DNS service is stopped or fails, websites will fail to resolve because adapters
  point to 127.0.0.1. The installer creates a restart-on-failure scheduled task, but always
  test service health before office-wide rollout.
- Uninstall resets active adapters to DHCP-provided DNS. If the office uses manually
  configured DNS, record it before installation and restore it after uninstall.
- This installer overwrites Chrome/Edge DnsOverHttpsMode policy values. Uninstall removes
  those values; if your organization had pre-existing values, restore them manually.
- This is an internal prototype. Do not deploy to all office PCs until it has passed
  allow/deny, reboot, network-change, and recovery tests on a spare device.
