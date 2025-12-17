package collector

const (
	QueryServerBasicInfo = `
SELECT
    -- Basic Server Info
    @@SERVERNAME AS ServerName,
    CAST(SERVERPROPERTY('MachineName') AS NVARCHAR(128)) AS MachineName,
    CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(128)) AS InstanceName,
    CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)) AS ProductVersion,
    CAST(SERVERPROPERTY('IsClustered') AS INT) AS IsClustered,
    CAST(SERVERPROPERTY('IsHadrEnabled') AS INT) AS IsHadrEnabled,

    -- Authentication
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows Authentication'
        WHEN 0 THEN 'SQL Server and Windows Authentication'
    END AS AuthenticationMode,

    'Unknown' AS ExtendedProtection
`

    QueryServerServiceAccount = `
SELECT
    servicename,
    service_account
FROM sys.dm_server_services
WHERE servicename LIKE 'SQL Server (%'
`

    QueryServerConfiguration = `
SELECT
    name,
    CAST(value AS INT) as val
FROM sys.configurations
WHERE name IN (
    'cross db ownership chaining',
    'xp_cmdshell',
    'clr enabled',
    'Ole Automation Procedures',
    'show advanced options',
    'scan for startup procs',
    'remote admin connections',
    'Ad Hoc Distributed Queries',
    'trustworthy'
)
`

	QueryServerPrincipals = `
SELECT
    p.name,
    p.principal_id,
    p.type_desc,
    p.is_disabled,
    p.is_fixed_role,
    p.create_date,
    p.modify_date,
    p.default_database_name,
    p.credential_id,
    SUSER_SID(p.name) AS sid,

    -- Get members for roles
    STUFF((
        SELECT ',' + mp.name
        FROM sys.server_role_members rm
        INNER JOIN sys.server_principals mp ON rm.member_principal_id = mp.principal_id
        WHERE rm.role_principal_id = p.principal_id
        FOR XML PATH('')
    ), 1, 1, '') AS members,

    -- Get roles this principal is a member of
    STUFF((
        SELECT ',' + rp.name
        FROM sys.server_role_members rm
        INNER JOIN sys.server_principals rp ON rm.role_principal_id = rp.principal_id
        WHERE rm.member_principal_id = p.principal_id
        FOR XML PATH('')
    ), 1, 1, '') AS member_of,

    -- Get Permissions
    STUFF((
        SELECT '|' +
            perm.state_desc + ':' +
            perm.permission_name + ':' +
            COALESCE(OBJECT_NAME(perm.major_id), '') + ':' +
            COALESCE(perm.class_desc, '')
        FROM sys.server_permissions perm
        WHERE perm.grantee_principal_id = p.principal_id
        FOR XML PATH('')
    ), 1, 1, '') AS permissions

FROM sys.server_principals p
`

	QueryDatabases = `
SELECT
    d.name,
    d.database_id,
    d.create_date,
    d.is_trustworthy_on,
    d.is_broker_enabled,
    d.is_encrypted,
    d.is_read_only,
    suser_sname(d.owner_sid) AS owner_name,
    d.owner_sid
FROM sys.databases d
`

	QueryDatabasePrincipals = `
SELECT
    p.name,
    p.principal_id,
    p.type_desc,
    p.create_date,
    p.modify_date,
    p.default_schema_name,
    p.is_fixed_role,
    p.sid, -- For SQL Users/Roles, this might be null or specific format
    p.owning_principal_id,

    -- Get members for roles
    STUFF((
        SELECT ',' + mp.name
        FROM sys.database_role_members rm
        INNER JOIN sys.database_principals mp ON rm.member_principal_id = mp.principal_id
        WHERE rm.role_principal_id = p.principal_id
        FOR XML PATH('')
    ), 1, 1, '') AS members,

    -- Get roles this principal is a member of
    STUFF((
        SELECT ',' + rp.name
        FROM sys.database_role_members rm
        INNER JOIN sys.database_principals rp ON rm.role_principal_id = rp.principal_id
        WHERE rm.member_principal_id = p.principal_id
        FOR XML PATH('')
    ), 1, 1, '') AS member_of,

    -- Get Permissions
    STUFF((
        SELECT '|' +
            perm.state_desc + ':' +
            perm.permission_name + ':' +
            COALESCE(OBJECT_NAME(perm.major_id), '') + ':' +
            COALESCE(perm.class_desc, '')
        FROM sys.database_permissions perm
        WHERE perm.grantee_principal_id = p.principal_id
        FOR XML PATH('')
    ), 1, 1, '') AS permissions,

    -- Linked Login (for Users mapped to Logins)
    (SELECT sp.name FROM sys.server_principals sp WHERE sp.sid = p.sid) AS server_login_name

FROM sys.database_principals p
`

    QueryLinkedServers = `
SELECT
    name,
    provider,
    product,
    data_source,
    is_linked
FROM sys.servers
WHERE is_linked = 1
`

    QueryCredentials = `
SELECT
    credential_id,
    name,
    credential_identity,
    create_date,
    modify_date
FROM sys.credentials
`

    QueryProxyAccounts = `
SELECT
    p.proxy_id,
    p.name AS proxy_name,
    p.credential_id,
    c.name AS credential_name,
    c.credential_identity,
    p.enabled,
    p.description,
    -- Get subsystems this proxy can access
    STUFF((
        SELECT ', ' + ss.subsystem
        FROM msdb.dbo.sysproxysubsystem ps
        INNER JOIN msdb.dbo.syssubsystems ss ON ps.subsystem_id = ss.subsystem_id
        WHERE ps.proxy_id = p.proxy_id
        FOR XML PATH('')
    ), 1, 2, '') AS subsystems,
    -- Get principals that can use this proxy (using sid column)
    STUFF((
        SELECT ', ' + SUSER_SNAME(spl.sid)
        FROM msdb.dbo.sysproxylogin spl
        WHERE spl.proxy_id = p.proxy_id
            AND SUSER_SNAME(spl.sid) IS NOT NULL
        FOR XML PATH('')
    ), 1, 2, '') AS authorized_principals
FROM msdb.dbo.sysproxies p
INNER JOIN sys.credentials c ON p.credential_id = c.credential_id
ORDER BY p.proxy_id
`
)
