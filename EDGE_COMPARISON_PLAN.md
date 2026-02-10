# MSSQLHound Edge Creation: PowerShell vs Go Comparison Plan

This document is a systematic comparison plan to identify where the Go version may produce different edges from the PowerShell version. Each section covers one category of edge creation, lists the relevant code locations in both versions, and describes the specific logic to compare.

---

## Overview of Structural Differences

| Aspect | PowerShell | Go |
|--------|-----------|-----|
| **Edge creation** | All in `Process-ServerInstance` (lines 9113-10285) | Split across `createEdges`, `createFixedRoleEdges`, `createServerPermissionEdges`, `createDatabasePermissionEdges` |
| **Fixed role handling** | Inline within miscellaneous section + separate securityadmin block | Dedicated `createFixedRoleEdges` function |
| **Ordering** | Permissions first, then structural, then AD/credential, then containment | Structural first, then fixed roles, then permissions, then AD/credential |
| **Deduplication** | May emit duplicates | Deduplicates via `principalsWithLogin` map |
| **AD resolution** | Calls `Resolve-DomainPrincipal` per login (LDAP validation) | Trusts collected SID data without per-login LDAP validation |

---

## CATEGORY 1: Containment Edges (MSSQL_Contains)

### Where to look
- **PS:** Lines 9707-9713 (Server->DB), 10231-10248 (Server->Principal), 10250-10283 (DB->Principal)
- **Go:** Lines 2198-2256 in `createEdges`

### What to compare
1. **Server -> Database:** Both iterate all databases. Should match.
2. **Server -> Server Principals:** PS explicitly checks `TypeDescription` for SERVER_ROLE, WINDOWS_LOGIN, WINDOWS_GROUP, SQL_LOGIN, ASYMMETRIC_KEY_MAPPED_LOGIN, CERTIFICATE_MAPPED_LOGIN. Go iterates ALL `ServerPrincipals` without filtering by type.
   - **POTENTIAL ISSUE:** Go may include principal types that PS excludes (e.g., if there are other TypeDescriptions in the collection). Verify that Go's server principal collection only collects the same types PS does.
3. **Database -> Database Principals:** PS checks for DATABASE_ROLE, APPLICATION_ROLE, and user types. Go iterates ALL `DatabasePrincipals`.
   - **POTENTIAL ISSUE:** Same as above — verify collection scope.

### Priority: MEDIUM
Contains edges are structural and unlikely to differ unless there are unexpected principal types.

---

## CATEGORY 2: Ownership Edges (MSSQL_Owns)

### Where to look
- **PS:** Lines 9715-9729 (DB ownership), 9797-9812 (Server role ownership), 9814-9832 (DB role ownership)
- **Go:** Lines 2262-2326 in `createEdges`

### What to compare
1. **Database ownership:** PS checks `OwnerObjectIdentifier` AND validates owner exists in ServerPrincipals. Go only checks `OwnerObjectIdentifier != ""`.
   - **POTENTIAL ISSUE:** Go may create Owns edges for databases whose owner is not found in ServerPrincipals (e.g., orphaned owners). PS skips these.
2. **Server role ownership:** PS checks `OwnerObjectIdentifier` and validates owner exists. Go only checks `TypeDescription == "SERVER_ROLE" && OwningObjectIdentifier != ""`.
   - **POTENTIAL ISSUE:** Same orphan issue as above.
3. **Database role ownership:** Same pattern — PS validates, Go doesn't.

### Priority: MEDIUM
Missing owner validation could lead to extra edges in Go for orphaned ownership references.

---

## CATEGORY 3: Membership Edges (MSSQL_MemberOf)

### Where to look
- **PS:** Lines 9731-9741 (server roles), 9755-9767 (database roles)
- **Go:** Lines 2332-2375 in `createEdges`

### What to compare
1. Both iterate `principal.MemberOf` and create edges. Logic appears identical.
2. Verify that the `MemberOf` collection is populated identically in both versions (check SQL queries in data collection).

### Priority: LOW
Straightforward iteration — unlikely to differ unless data collection differs.

---

## CATEGORY 4: Login-to-User Mapping (MSSQL_IsMappedTo)

### Where to look
- **PS:** Lines 9783-9795
- **Go:** Lines 2382-2403

### What to compare
1. PS iterates databases and checks if each DB principal has a `LoginSID` mapping. Go checks if `principal.ServerLogin != nil`.
2. Verify that `linkDatabaseUsersToServerLogins()` in Go's mssql client populates `ServerLogin` with the same logic PS uses to match logins to database users.

### Priority: MEDIUM
The linking logic in `mssql/client.go` may differ from PS's approach (PS matches by SID, Go may match by name or other criteria).

---

## CATEGORY 5: Fixed Role Edges

### Where to look
- **PS:** Lines 9743-9753 (securityadmin -> GrantAnyPermission), 9769-9781 (db_securityadmin -> GrantAnyDBPermission). Note: sysadmin->ControlServer and db_owner->Control/ControlDB edges are created by PS as **explicit permission edges** not as fixed role edges.
- **Go:** Lines 3624-3976 in `createFixedRoleEdges`

### What to compare

#### 5a. sysadmin -> ControlServer
- **PS:** Created via explicit CONTROL SERVER permission processing (server gets an implicit CONTROL SERVER for sysadmin role, or it might be handled differently — need to check if PS creates this as an explicit permission or separately).
- **Go:** Created in `createFixedRoleEdges` line 3634.
- **POTENTIAL ISSUE:** PS may not create sysadmin->ControlServer as a fixed role edge but instead relies on it showing up in explicit permissions. Go creates it explicitly. This could cause DUPLICATE edges if sysadmin also has an explicit CONTROL SERVER permission recorded. Or PS may MISS it if sysadmin doesn't have an explicit CONTROL SERVER permission row. **Needs verification of what permissions sysadmin reports.**

#### 5b. securityadmin -> GrantAnyPermission
- **PS:** Line 9748 — explicit loop looking for securityadmin role.
- **Go:** Line 3653 — in `createFixedRoleEdges`.
- Should match.

#### 5c. securityadmin -> AlterAnyLogin
- **PS:** NOT explicitly created as a fixed role edge. PS only creates AlterAnyLogin from explicit `ALTER ANY LOGIN` permissions.
- **Go:** Line 3671 — created in `createFixedRoleEdges`.
- **POTENTIAL ISSUE:** If securityadmin doesn't report `ALTER ANY LOGIN` as an explicit permission, PS would MISS this edge. Go creates it explicitly. This could be a MISSING edge in PS, or a DUPLICATE in Go if securityadmin also has an explicit permission.

#### 5d. securityadmin -> ChangePassword (to SQL logins)
- **PS:** NOT explicitly created as a fixed role edge. Only created via explicit `ALTER ANY LOGIN` permission processing.
- **Go:** Lines 3689-3727 — created in `createFixedRoleEdges`.
- **POTENTIAL ISSUE:** Same as 5c — depends on whether securityadmin reports `ALTER ANY LOGIN` explicitly.

#### 5e. ##MS_LoginManager## -> AlterAnyLogin + ChangePassword
- **PS:** NOT explicitly handled as a fixed role — depends on explicit permission processing.
- **Go:** Lines 3728-3785 — explicit in `createFixedRoleEdges`.
- **POTENTIAL ISSUE:** If SQL Server 2022 reports these as explicit permissions, PS would handle them. If not, PS misses them. Go handles them explicitly.

#### 5f. ##MS_DatabaseConnector## -> ConnectAnyDatabase
- **PS:** NOT explicitly handled as a fixed role.
- **Go:** Lines 3787-3804.
- Same issue as above.

#### 5g. db_owner -> Control + ControlDB
- **PS:** Created via explicit CONTROL permission processing on the DATABASE class.
- **Go:** Lines 3817-3854 — explicit in `createFixedRoleEdges`.
- **POTENTIAL ISSUE:** Could duplicate if db_owner also shows up with explicit CONTROL permission.

#### 5h. db_securityadmin -> GrantAnyDBPermission + AlterAnyAppRole + AlterAnyDBRole
- **PS:** GrantAnyDBPermission at line 9775. AlterAnyAppRole/AlterAnyDBRole NOT explicitly created for fixed roles.
- **Go:** Lines 3860-3965.
- **POTENTIAL ISSUE:** Go creates more edges for db_securityadmin than PS does as fixed role edges. PS relies on explicit permissions.

#### 5i. db_securityadmin -> AddMember (to user-defined roles) + ChangePassword (to app roles)
- **PS:** NOT explicitly created as fixed role edges.
- **Go:** Lines 3918-3965.
- **POTENTIAL ISSUE:** Go creates these explicitly; PS only creates them if db_securityadmin has explicit ALTER ANY ROLE / ALTER ANY APPLICATION ROLE permissions.

### Priority: **HIGH**
This is the most likely area for discrepancies. Go creates fixed role edges explicitly while PS relies on these showing up as explicit permissions. The key question is: **do fixed server/database roles report their implicit permissions in the sys.server_permissions / sys.database_permissions views?** If yes, PS handles them via the permission processing loop. If no, PS misses them and Go is correct.

---

## CATEGORY 6: Server Permission Edges

### Where to look
- **PS:** Lines 9113-9392
- **Go:** Lines 3979-4474 in `createServerPermissionEdges`

### What to compare (permission by permission)

#### 6a. CONTROL SERVER
- Both: principal -> server (ControlServer). Should match.

#### 6b. CONNECT SQL
- Both: principal -> server (Connect), only if not disabled. Should match.

#### 6c. CONNECT ANY DATABASE
- Both: principal -> server (ConnectAnyDatabase). Should match.

#### 6d. CONTROL (on SERVER_PRINCIPAL)
- Both create: Control (non-traversable), ExecuteAs (if login), AddMember+ChangeOwner (if role with conditions).
- **KEY DIFFERENCE in ChangeOwner:** PS only creates ChangeOwner if `canAlterRole` is true (meaning user is member of fixed role or it's user-defined). Go ALWAYS creates ChangeOwner for server roles regardless of canAlterRole.
  - **PS (line 9340-9341):** AddMember and ChangeOwner are both gated behind `if ($canAlterRole)`.
  - **Go (line 4145-4161):** ChangeOwner is created UNCONDITIONALLY for server roles, only AddMember is gated behind `canAddMember`.
  - **POTENTIAL BUG IN GO:** Go creates ChangeOwner edges even when canAddMember is false, which PS doesn't do.

#### 6e. ALTER (on SERVER_PRINCIPAL)
- Both create Alter + conditional AddMember. Logic matches.

#### 6f. ALTER ANY LOGIN
- Both create AlterAnyLogin edge to server + ChangePassword edges to SQL logins.
- **KEY DIFFERENCE in ChangePassword:** PS has a fallback case where if `$patchedResults -eq $null`, it does NOT create the edge (line 9218-9220: "No patch info - assume not vulnerable to reduce false positives"). Go calls `shouldCreateChangePasswordEdge()` which may handle this differently.
  - **POTENTIAL ISSUE:** Need to verify Go's `shouldCreateChangePasswordEdge` logic matches PS's null-patchedResults behavior.

#### 6g. ALTER ANY SERVER ROLE
- Both create AlterAnyServerRole edge + AddMember edges to roles. Logic matches.

#### 6h. IMPERSONATE
- Both create Impersonate + ExecuteAs. Should match.

#### 6i. IMPERSONATE ANY LOGIN
- Both create ImpersonateAnyLogin to server. Should match.

#### 6j. TAKE OWNERSHIP
- Both create TakeOwnership + conditional ChangeOwner (if SERVER_ROLE). Should match.

### Priority: **HIGH**
The CONTROL->ChangeOwner difference (6d) is a confirmed logic discrepancy.

---

## CATEGORY 7: Database Permission Edges

### Where to look
- **PS:** Lines 9394-9653
- **Go:** Lines 4477-5041 in `createDatabasePermissionEdges`

### What to compare (permission by permission)

#### 7a. CONTROL on DATABASE
- Both create Control + ControlDB. Should match.

#### 7b. CONTROL on DATABASE_PRINCIPAL
- Both create Control (non-traversable).
- For DATABASE_ROLE: Both create AddMember + ChangeOwner.
- For users (WINDOWS_USER, SQL_USER, etc.): Both create ExecuteAs.
- For APPLICATION_ROLE: Both skip (no extra edges).
- **KEY DIFFERENCE:** PS checks target TypeDescription against a specific list for user types. Go uses `isUser` flag. Verify the sets match.

#### 7c. CONNECT on DATABASE
- **PS (line 9553):** Explicitly filters out APPLICATION_ROLE with `if ($perm.ClassDesc -ne "APPLICATION_ROLE")`.
- **Go (line 4628):** Filters by `perm.ClassDesc == "DATABASE"`.
- **POTENTIAL ISSUE:** PS uses `ClassDesc -ne "APPLICATION_ROLE"` as the filter, while Go uses `ClassDesc == "DATABASE"`. If a CONNECT permission has a ClassDesc other than DATABASE or APPLICATION_ROLE, PS would include it but Go wouldn't. Need to verify what ClassDesc values are possible for CONNECT permissions.

#### 7d. ALTER on DATABASE
- Both create Alter edge + AddMember (to roles) + ChangePassword (to app roles).
- Logic for db_owner check and fixed role filtering matches.

#### 7e. ALTER on DATABASE_PRINCIPAL
- **PS (lines 9459-9481):** Creates Alter, then for DATABASE_ROLE creates BOTH Alter AND AddMember (note: creates Alter TWICE at lines 9464 and 9470).
- **Go (lines 4730-4781):** Creates Alter once, then AddMember for DATABASE_ROLE.
- **POTENTIAL ISSUE:** PS creates a DUPLICATE Alter edge for DATABASE_ROLE targets (lines 9464 and 9470). Go only creates one Alter edge. This would result in PS having one extra Alter edge per DATABASE_ROLE target with ALTER permission.

#### 7f. ALTER ANY APPLICATION ROLE
- Both create AlterAnyAppRole + ChangePassword to individual app roles. Should match.

#### 7g. ALTER ANY ROLE
- Both create AlterAnyDBRole + AddMember to eligible roles. Logic matches.

#### 7h. IMPERSONATE on DATABASE_PRINCIPAL
- **PS (line 9607):** Explicitly checks target is a user type (WINDOWS_USER, WINDOWS_GROUP, SQL_USER, etc.).
- **Go (line 4893):** Only checks `perm.ClassDesc == "DATABASE_PRINCIPAL"` — does NOT filter by target type.
- **POTENTIAL ISSUE:** Go may create Impersonate/ExecuteAs edges to DATABASE_ROLEs or APPLICATION_ROLEs, which PS would skip. This could produce extra edges in Go. Verify whether IMPERSONATE can actually be granted on roles/app roles.

#### 7i. TAKE OWNERSHIP on DATABASE
- Both create TakeOwnership + ChangeOwner to all DATABASE_ROLEs. Should match.

#### 7j. TAKE OWNERSHIP on specific object
- **PS (lines 9635-9647):** Uses `Set-EdgeContext` to resolve target, then creates TakeOwnership + conditional ChangeOwner.
- **Go (lines 4984-5036):** Looks up target in `db.DatabasePrincipals` by ObjectIdentifier, creates edges if found.
- **POTENTIAL ISSUE:** Go lookups by ObjectIdentifier might not find the target if OID format differs. PS uses Set-EdgeContext which resolves via permission metadata.

### Priority: **HIGH**
Multiple differences identified, especially in ALTER (duplicate Alter), IMPERSONATE (missing type filter), and CONNECT (different ClassDesc filter).

---

## CATEGORY 8: Linked Server Edges (MSSQL_LinkedTo, MSSQL_LinkedAsAdmin)

### Where to look
- **PS:** Lines 9926-9996
- **Go:** Lines 2434-2531

### What to compare
1. **Source resolution:** PS resolves source via `Resolve-DataSourceToSid`. Go resolves via `resolveLinkedServerSourceID`. Verify these produce the same ObjectIdentifier.
2. **Target resolution:** PS uses `$linkedServer.ResolvedObjectIdentifier`. Go uses `linked.ResolvedObjectIdentifier` with fallback to `linked.DataSource`.
   - **POTENTIAL ISSUE:** Go falls back to `linked.DataSource` when `ResolvedObjectIdentifier` is empty. PS always uses `ResolvedObjectIdentifier`. If resolution fails, Go would create an edge with a raw DataSource string while PS might skip it (need to check what PS does when ResolvedObjectIdentifier is empty).
3. **LinkedAsAdmin conditions:** Both check the same conditions (SQL login, admin privs, mixed mode). Should match.
4. **Properties:** Both include the same property set. Should match.

### Priority: MEDIUM

---

## CATEGORY 9: Trustworthy Database Edges (MSSQL_IsTrustedBy, MSSQL_ExecuteAsOwner)

### Where to look
- **PS:** Lines 9657-9705
- **Go:** Lines 2534-2605

### What to compare
1. **IsTrustedBy:** Both create if database is trustworthy. Should match.
2. **ExecuteAsOwner:** Both check if owner has sysadmin/securityadmin/CONTROL SERVER/IMPERSONATE ANY LOGIN.
   - PS uses `Get-EffectivePermissions` and `Get-NestedRoleMembership`.
   - Go uses `hasNestedRoleMembership` and `hasEffectivePermission`.
   - Verify these helper functions produce the same results.
3. **Owner lookup:** PS uses `$db.OwnerPrincipalID` to find owner. Go uses `owner.ObjectIdentifier == db.OwnerObjectIdentifier`.
   - **POTENTIAL ISSUE:** Different lookup keys (PrincipalID vs ObjectIdentifier) could yield different results if the mapping is inconsistent.

### Priority: MEDIUM

---

## CATEGORY 10: Computer-Server Edges (MSSQL_HostFor, MSSQL_ExecuteOnHost)

### Where to look
- **PS:** Lines 9834-9846
- **Go:** Lines 2612-2646

### What to compare
1. **Computer SID resolution:** PS calls `Resolve-DomainPrincipal $serverInfo.Hostname` to get the SID dynamically. Go uses `serverInfo.ComputerSID` which was pre-resolved during data collection.
   - **POTENTIAL ISSUE:** If `ComputerSID` is not populated in Go (e.g., LDAP resolution failed), Go would skip both edges entirely. PS always resolves at this point.
2. Both create the same two edges (HostFor and ExecuteOnHost) with matching source/target.

### Priority: MEDIUM

---

## CATEGORY 11: AD Principal -> Login Edges (MSSQL_HasLogin)

### Where to look
- **PS:** Lines 10083-10227
- **Go:** Lines 2652-2847

### What to compare

#### 11a. Domain principal HasLogin edges (S-1-5-21-* SIDs)
- **PS (lines 10157-10196):** Filters to `enabledDomainPrincipalsWithConnectSQL`, then calls `Resolve-DomainPrincipal` to VALIDATE the domain account still exists in AD. Only creates edge if resolution succeeds.
- **Go (lines 2655-2715):** Filters similarly (enabled, domain SID, has CONNECT SQL) but does NOT validate via AD/LDAP. Creates edge based purely on collected SQL metadata.
- **KEY DIFFERENCE:** PS validates AD existence; Go doesn't.
  - **Impact:** Go may create HasLogin edges for deleted/orphaned AD accounts that PS would skip.
  - **Assessment:** This is a design choice (documented). Go intentionally includes these because orphaned SIDs can still be attack-relevant.

#### 11b. CONNECT SQL check
- **PS:** Uses pre-filtered list `$enabledDomainPrincipalsWithConnectSQL`.
- **Go:** Checks permissions inline AND checks sysadmin/securityadmin membership (implies CONNECT SQL).
- **POTENTIAL ISSUE:** Does PS's `$enabledDomainPrincipalsWithConnectSQL` also consider sysadmin/securityadmin membership as implying CONNECT SQL? Need to check how this list is built (around lines 7500-7600 in PS).

#### 11c. Local group HasLogin edges
- **PS (lines 10087-10127):** Iterates `LocalGroupsWithLogins` dictionary. Creates HasLogin edge AND MemberOf edge for each group member.
- **Go (lines 2749-2782):** Iterates `LocalGroupsWithLogins` slice. Creates HasLogin edge but does NOT create MemberOf edges for group members.
- **KEY DIFFERENCE:** Go is MISSING MemberOf edges for local group members.
  - **POTENTIAL BUG IN GO:** PS creates `MemberOf` edges (line 10120-10122) from group members to the local group. Go does NOT create these edges. This means Go is missing the link between individual AD principals and the local groups that have SQL logins.

#### 11d. BUILTIN group HasLogin edges (S-1-5-32-*)
- PS handles these alongside domain principals in the same loop.
- Go has a separate fallback branch (lines 2784-2847) that only runs when `LocalGroupsWithLogins` is nil.
- **POTENTIAL ISSUE:** If `LocalGroupsWithLogins` is populated but incomplete, Go might miss BUILTIN groups that PS would catch.

#### 11e. ObjectIdentifier format for local groups
- Both use `{serverFQDN}-{SID}` format. Should match.

### Priority: **HIGH**
Missing MemberOf edges (11c) is likely a real bug. AD validation difference (11a) is a design choice.

---

## CATEGORY 12: CoerceAndRelayToMSSQL

### Where to look
- **PS:** Lines 10134-10152
- **Go:** Lines 2717-2743

### What to compare
1. **Condition:** Both check EPA == "Off" and login name ends with `$`.
2. **Source SID:** PS uses `"$script:Domain-S-1-5-11"`. Go uses `"S-1-5-11"` with optional domain prefix.
   - **POTENTIAL ISSUE:** PS always prefixes with domain. Go only prefixes if `c.config.Domain != ""`. If domain is not set in Go config, the SID would be just `S-1-5-11` without domain prefix, which wouldn't match PS output.

### Priority: MEDIUM

---

## CATEGORY 13: Service Account Edges

### Where to look
- **PS:** Lines 9847-9924
- **Go:** Lines 2902-3019

### What to compare

#### 13a. ServiceAccountFor
- Both create from service account SID to server. Should match.
- **POTENTIAL ISSUE:** Go filters to domain accounts only (`S-1-5-21-*`). PS only checks if `ObjectIdentifier` exists. If PS creates ServiceAccountFor for non-domain accounts, Go would miss them.

#### 13b. HasSession
- **PS (line 9858-9868):** Skips machine account (`$serverHostname$`), SYSTEM, LOCAL SERVICE, NETWORK SERVICE.
- **Go (lines 2959-2980):** Skips built-in accounts + computer account name + computer account SID + converted-from-built-in flag.
- Go has extra checks (`isComputerAccountSID`, `isConvertedFromBuiltIn`) that PS doesn't have.
- **POTENTIAL ISSUE:** If a service account was "converted from built-in" (e.g., LocalSystem was resolved to the computer account), Go would skip HasSession but PS would not (PS only checks the name patterns).

#### 13c. GetAdminTGS
- **PS (line 9903-9915):** Checks `$serverInfo.IsAnyDomainPrincipalSysadmin` and includes filtered domain principal lists in edge properties.
- **Go (lines 2982-2999):** Checks `len(domainPrincipalsWithAdmin) > 0` and does NOT include domain principal lists in edge properties.
- **KEY DIFFERENCE:** Go computes admin status differently (uses `hasNestedRoleMembership` + `hasEffectivePermission` which checks sysadmin, securityadmin, CONTROL SERVER, IMPERSONATE ANY LOGIN). PS uses `IsAnyDomainPrincipalSysadmin` flag.
- **POTENTIAL ISSUE:** Go's `domainPrincipalsWithAdmin` includes securityadmin, CONTROL SERVER, and IMPERSONATE ANY LOGIN holders. PS's `IsAnyDomainPrincipalSysadmin` might only check sysadmin. If so, Go would create GetAdminTGS in more cases than PS.
- Also Go doesn't add the `domainPrincipalsWithControlServer`, `domainPrincipalsWithSysadmin`, etc. properties.

#### 13d. GetTGS
- Both create from service account to each enabled domain login with CONNECT SQL. Should match if the CONNECT SQL filter is the same (see 11b).

### Priority: **HIGH**
GetAdminTGS condition differs, and HasSession exclusion logic differs.

---

## CATEGORY 14: Credential Edges

### Where to look
- **PS:** Lines 10000-10081
- **Go:** Lines 3025-3148

### What to compare

#### 14a. HasMappedCred
- **PS (lines 10001-10022):** Checks `HasCredential` property on principal, matches to `serverInfo.Credentials` by name, requires `ResolvedSID`.
- **Go (lines 3026-3061):** Checks `MappedCredential` on principal, filters by domain credential (contains `\` or `@`), uses ResolvedSID or falls back to CredentialIdentity.
- **KEY DIFFERENCE:** PS requires `ResolvedSID` (skips if null). Go falls back to `CredentialIdentity` if `ResolvedSID` is empty.
  - **Impact:** Go may create edges with non-SID targets that PS would skip.

#### 14b. HasProxyCred
- **PS (lines 10024-10057):** Checks `IsDomainPrincipal` and `ResolvedSID`, splits `AuthorizedPrincipals` by comma, matches by name.
- **Go (lines 3068-3112):** Checks credential contains `\` or `@`, iterates `proxy.Logins`, matches by name.
- **POTENTIAL ISSUE:** PS uses `IsDomainPrincipal` flag while Go checks for `\` or `@` in identity. These could differ for some credential types. Also PS requires `ResolvedSID`; Go falls back to CredentialIdentity.

#### 14c. HasDBScopedCred
- **PS (lines 10059-10081):** Checks `IsDomainPrincipal` and `ResolvedSID`.
- **Go (lines 3119-3148):** Checks credential contains `\` or `@`, uses ResolvedSID or falls back to CredentialIdentity.
- Same pattern of differences as above.

### Priority: MEDIUM

---

## CATEGORY 15: GrantAnyPermission / GrantAnyDBPermission Edges

### Where to look
- **PS:** Lines 9743-9753 (securityadmin -> GrantAnyPermission), 9769-9781 (db_securityadmin -> GrantAnyDBPermission)
- **Go:** In `createFixedRoleEdges` lines 3653, 3862

### What to compare
1. PS loops through all ServerPrincipals to find securityadmin by name. Go loops through ServerPrincipals checking `IsFixedRole`.
2. PS loops through all databases and their principals to find db_securityadmin. Go does the same.
3. **POTENTIAL ISSUE:** Go uses `principal.IsFixedRole` flag, which must be correctly set during collection. If this flag is wrong, edges would be missing or duplicated.

### Priority: LOW

---

## Summary of Identified Issues (by Priority)

### HIGH Priority (Most Likely to Cause Discrepancies)

| # | Issue | Category | Description |
|---|-------|----------|-------------|
| 1 | **Missing MemberOf for local groups** | 11c | Go doesn't create MemberOf edges from local group members to the group node |
| 2 | **Fixed role edges vs explicit permissions** | 5 | Go creates edges explicitly for fixed roles; PS relies on them appearing as explicit permissions. Could cause duplicates or missing edges |
| 3 | **CONTROL -> ChangeOwner unconditional** | 6d | Go creates ChangeOwner for all server roles with CONTROL, regardless of canAddMember. PS gates both AddMember and ChangeOwner behind canAlterRole |
| 4 | **DB IMPERSONATE missing type filter** | 7h | Go doesn't filter IMPERSONATE targets by type (user types only). May create edges to roles/app roles that PS would skip |
| 5 | **DB ALTER duplicate Alter edge** | 7e | PS creates Alter TWICE for DATABASE_ROLE targets (lines 9464+9470). Go creates it once. PS has extra edges |
| 6 | **GetAdminTGS broader condition** | 13c | Go includes securityadmin/CONTROL SERVER/IMPERSONATE ANY LOGIN in admin check; PS may only check sysadmin |

### MEDIUM Priority

| # | Issue | Category | Description |
|---|-------|----------|-------------|
| 7 | **Ownership edge validation** | 2 | Go doesn't validate that the owner exists in ServerPrincipals before creating Owns edges |
| 8 | **AD validation for HasLogin** | 11a | Go doesn't validate AD account existence via LDAP (design choice) |
| 9 | **CoerceAndRelay domain prefix** | 12 | Go may omit domain prefix from Authenticated Users SID if config.Domain is empty |
| 10 | **Computer SID availability** | 10 | Go requires pre-resolved ComputerSID; PS resolves at edge-creation time |
| 11 | **Linked server target fallback** | 8 | Go falls back to DataSource when ResolvedObjectIdentifier is empty |
| 12 | **Credential edge fallback** | 14 | Go falls back to CredentialIdentity when ResolvedSID is empty; PS requires ResolvedSID |
| 13 | **HasSession extra exclusions** | 13b | Go has additional exclusion conditions (ConvertedFromBuiltIn, SID match) |
| 14 | **DB CONNECT ClassDesc filter** | 7c | PS uses `ClassDesc -ne APPLICATION_ROLE`, Go uses `ClassDesc == DATABASE` |
| 15 | **ChangePassword null patch handling** | 6f | PS skips ChangePassword if patchedResults is null; verify Go's `shouldCreateChangePasswordEdge` matches |
| 16 | **Login-to-DBUser mapping logic** | 4 | Verify Go's `linkDatabaseUsersToServerLogins` matches PS's SID-based mapping |

### LOW Priority

| # | Issue | Category | Description |
|---|-------|----------|-------------|
| 17 | **Contains edge type filtering** | 1 | Go includes all principals; PS filters by TypeDescription |
| 18 | **MemberOf iteration** | 3 | Should match if data collection is identical |
| 19 | **IsFixedRole flag accuracy** | 15 | Verify Go correctly sets IsFixedRole during collection |

---

## Recommended Investigation Order

1. **Issue #2 (Fixed role edges):** Run both against same server, compare edge counts per kind. This will reveal duplicates from Go's explicit fixed role handling.
2. **Issue #1 (Missing MemberOf):** Check Go's `createEdges` for any MemberOf edge creation for local group members. If absent, this is a clear bug.
3. **Issue #3 (ChangeOwner unconditional):** Read Go lines 4145-4161 to confirm ChangeOwner is not gated behind canAddMember.
4. **Issue #4 (IMPERSONATE type filter):** Read Go lines 4891-4937 to confirm no target type check exists.
5. **Issue #6 (GetAdminTGS):** Compare how `IsAnyDomainPrincipalSysadmin` is set in PS vs how Go computes `domainPrincipalsWithAdmin`.
6. **Issues #7-16:** Investigate during testing with real data.

---

## Data Collection Comparison (Out of Scope but Important)

Differences in edge creation may also stem from differences in **data collection** (SQL queries). Key areas to verify:
- Are the same SQL queries used for collecting server principals, permissions, database principals?
- Does Go's SID conversion (`convertHexSIDToString`) produce the same SIDs as PowerShell's .NET conversion?
- Are ObjectIdentifier formats identical between versions?
- Does Go's `IsFixedRole` detection match PS's logic?

These should be compared separately in a data collection audit.
