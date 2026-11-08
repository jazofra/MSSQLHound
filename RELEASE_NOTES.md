# MSSQLHound Release Notes
## Unreleased
- Cross-domain trust support:
  - Passively read the home domain's trusts, so logins from trusted domains get correctly named, SID-keyed AD nodes and are no longer classified as machine-local groups.
  - Add `--follow-trusts`, `--trust-depth` and `--domain-dc` to resolve principals and linked servers in trusting domains, and to enumerate and collect their SQL Servers.
- Fix `DOMAIN\name` and foreign SID lookups matching same-named or ForeignSecurityPrincipal objects in the home domain.
- Fix computer SID lookups by FQDN, which never matched in AD.
- Avoid re-binding an LDAP client after a failed connection (lockout safety).

## Version 2.0.4 (June 29, 2026)
- Move AD nodes/edges to separate file to prevent accidental deletion based on source_kind

## Version 2.0.3 (June 8, 2026)
- Add --scan-all-computer-ports and --port-check-timeout options
- Fix LDAP bind fail fallback when channel binding required

## Version 2.0.2 (May 7, 2026)
- LDAP bind fail fallback to ADSI when channel binding required
- Deduplicate DNS resolution for --scan-all-computers
- Remove PowerShell fallback

## Version 2.0.1 (May 5, 2026)
- Add CVE-2025-49758 to MSSQL_Server node properties

## Version 2.0 (April 23, 2026)
- Initial Go release

## Version 1.1 (December 22, 2025)
- Add unprivileged EPA checks based on [RelayInformer](https://github.com/zyn3rgy/RelayInformer) by Nick Powers (@zyn3rgy) and Matt Creel (@Tw1sm)
- Account for [CVE-2025-49758](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-49758) patch

## Version 1.0 (July 28, 2025)
- Initial Release
