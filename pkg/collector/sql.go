package collector

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/SpecterOps/MSSQLHound/pkg/models"
    "github.com/SpecterOps/MSSQLHound/pkg/utils"
	_ "github.com/microsoft/go-mssqldb"
)

type MSSQLCollector struct {
	ConnectionString string
	Host             string
	Port             int
	InstanceName     string
    Resolver         models.PrincipalResolver
}

func NewMSSQLCollector(host string, port int, instance string, username string, password string, domain string, authType string, resolver models.PrincipalResolver) *MSSQLCollector {
	// Build connection string
	var connStr string
	if authType == "Windows" {
		connStr = fmt.Sprintf("server=%s;port=%d;integrated security=true;", host, port)
	} else {
		connStr = fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;", host, port, username, password)
	}

    // Instance handling (if using SQL Browser resolution, go-mssqldb handles 'server=host\instance')
    if instance != "" && instance != "MSSQLSERVER" {
        if port == 0 {
             connStr = fmt.Sprintf("server=%s\\%s;", host, instance)
             if authType == "Windows" {
                 connStr += "integrated security=true;"
             } else {
                 connStr += fmt.Sprintf("user id=%s;password=%s;", username, password)
             }
        }
    }

	return &MSSQLCollector{
		ConnectionString: connStr,
		Host:             host,
		Port:             port,
		InstanceName:     instance,
        Resolver:         resolver,
	}
}

// BuildStubInfo attempts to resolve the host to a SID and create a basic info object
// regardless of whether we can connect to the SQL instance.
func (c *MSSQLCollector) BuildStubInfo(ctx context.Context) *models.MSSQLServerInfo {
    info := &models.MSSQLServerInfo{
        Name:         c.Host, // Default to host
        InstanceName: c.InstanceName,
        Port:         c.Port,
    }

    // Try to resolve host SID (Computer Account)
    if c.Resolver != nil {
        // Append $ to search for computer account
        hostToResolve := c.Host
        if !strings.HasSuffix(hostToResolve, "$") {
             // Basic heuristic: assume computer account
             // But if it's an IP, this will fail gracefully
             // If it is a FQDN, we extract the shortname?
             // Resolver handles FQDN/Shortname.
             hostToResolve += "$"
        }

        sid, dn, cls, err := c.Resolver.Resolve(hostToResolve)
        if err == nil && sid != "" && strings.EqualFold(cls, "computer") {
            info.HostSID = sid
            info.HostDN = dn
            info.HostName = c.Host // Or extract from DN
        }
    }

    // Set object identifier based on best available info
    // Format: SID:InstanceName (if named) or SID:Port (if default)
    suffix := fmt.Sprintf("%d", c.Port)
    if info.InstanceName != "" && info.InstanceName != "MSSQLSERVER" {
        suffix = strings.ToUpper(info.InstanceName)
    }

    if info.HostSID != "" {
        info.ObjectIdentifier = fmt.Sprintf("%s:%s", info.HostSID, suffix)
    } else {
        // Fallback to HOST:PORT if no SID resolved (e.g. IP address or offline)
        info.ObjectIdentifier = fmt.Sprintf("%s:%s", strings.ToUpper(c.Host), suffix)
    }

    return info
}

func (c *MSSQLCollector) Collect(ctx context.Context, info *models.MSSQLServerInfo) error {
	db, err := sql.Open("sqlserver", c.ConnectionString)
	if err != nil {
		return fmt.Errorf("failed to open connection: %v", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to connect to server %s: %v", c.Host, err)
	}

	// 1. Server Info (Critical - overwrites Stub if successful)
	if err := c.collectServerInfo(ctx, db, info); err != nil {
		return fmt.Errorf("collectServerInfo: %v", err)
	}

    // Re-evaluate ObjectIdentifier if we got a real @@SERVERNAME but NO HostSID?
    // Actually, stick to HostSID if we have it.
    // If we didn't have HostSID before, maybe we can get it now via SQL? (unlikely without xp_cmdshell)
    // So we keep the one from BuildStubInfo.

	// 2. Server Principals (Best Effort)
	if err := c.collectServerPrincipals(ctx, db, info); err != nil {
        // Log warning
        fmt.Printf("Warning: Failed to collect server principals from %s: %v\n", info.Name, err)
	}

	// 3. Databases (Best Effort)
	if err := c.collectDatabases(ctx, db, info); err != nil {
        fmt.Printf("Warning: Failed to collect databases from %s: %v\n", info.Name, err)
	}

    // 4. Database Principals (Loop through DBs)
    for i := range info.Databases {
        if err := c.collectDatabasePrincipals(ctx, db, &info.Databases[i]); err != nil {
            // Log warning, continue
        }
    }

	// 5. Credentials
	if err := c.collectCredentials(ctx, db, info); err != nil {
        // Warning
    }

    // 6. Proxy Accounts (Best Effort - requires msdb permissions)
    if err := c.collectProxyAccounts(ctx, db, info); err != nil {
        fmt.Printf("Warning: Failed to collect proxy accounts from %s: %v\n", info.Name, err)
    }

    // 7. Linked Servers
    if err := c.collectLinkedServers(ctx, db, info); err != nil {
        // Warning
    }

	return nil
}

func (c *MSSQLCollector) collectServerInfo(ctx context.Context, db *sql.DB, info *models.MSSQLServerInfo) error {
    // 1. Basic Info
	row := db.QueryRowContext(ctx, QueryServerBasicInfo)

    var serverName, machineName, instanceName, prodVer, authMode, extProt string
	var isClustered, isHadr int

    err := row.Scan(
        &serverName, &machineName, &instanceName, &prodVer, &isClustered, &isHadr,
        &authMode, &extProt,
    )
    if err != nil {
        return err
    }

    info.Name = serverName
    info.InstanceName = instanceName // Ensure we capture instance name
    info.Version = prodVer
    info.IsMixedModeAuthEnabled = (authMode == "SQL Server and Windows Authentication")

    // 2. Service Account (Privileged)
    row = db.QueryRowContext(ctx, QueryServerServiceAccount)
    var svcName, svcAccount string
    if err := row.Scan(&svcName, &svcAccount); err == nil {
        info.ServiceAccounts = []models.ServiceAccount{{Name: svcAccount}}
    }

    // 3. Configurations
    rows, err := db.QueryContext(ctx, QueryServerConfiguration)
    if err == nil {
        defer rows.Close()
        for rows.Next() {
            var name string
            var val int
            if err := rows.Scan(&name, &val); err == nil {
                switch name {
                case "cross db ownership chaining": info.CrossDbOwnershipChaining = val
                case "xp_cmdshell": info.XpCmdshell = val
                case "clr enabled": info.ClrEnabled = val
                case "Ole Automation Procedures": info.OleAutomationProcedures = val
                case "show advanced options": info.ShowAdvancedOptions = val
                case "scan for startup procs": info.ScanForStartupProcs = val
                case "remote admin connections": info.RemoteAdminConnections = val
                case "Ad Hoc Distributed Queries": info.AdHocDistributedQueries = val
                case "trustworthy": info.Trustworthy = val
                }
            }
        }
    }

	return nil
}

func (c *MSSQLCollector) collectServerPrincipals(ctx context.Context, db *sql.DB, info *models.MSSQLServerInfo) error {
	rows, err := db.QueryContext(ctx, QueryServerPrincipals)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var p models.ServerPrincipal
        var sid []byte
        var memberStr, memberOfStr, permStr sql.NullString
        var createDate, modifyDate, defaultDB sql.NullString
        var credentialID sql.NullString

		if err := rows.Scan(
            &p.Name, &p.PrincipalID, &p.TypeDescription, &p.IsDisabled, &p.IsFixedRole,
            &createDate, &modifyDate, &defaultDB, &credentialID, &sid,
            &memberStr, &memberOfStr, &permStr,
        ); err != nil {
			return err
		}

        sddl := utils.ConvertSidToSddl(sid)
        if sddl != "" {
            p.ObjectIdentifier = sddl
            p.SecurityIdentifier = sddl
        } else {
            // SQL Login or unresolved
            p.ObjectIdentifier = fmt.Sprintf("%s@%s", p.Name, info.ObjectIdentifier)
        }

        p.CreateDate = createDate.String
        p.ModifyDate = modifyDate.String
        p.DefaultDatabaseName = defaultDB.String
        p.SQLServerName = info.Name

        // Link Credential if exists
        if credentialID.Valid {
             // We can't link directly to the Credential object yet because we haven't collected them.
             // But we can store the ID to link later in Converter.
             // Or better, we populate a dummy credential with just ID for now.
             p.HasCredential = &models.Credential{CredentialId: credentialID.String}
        }

        // Parse Members
        if memberStr.Valid && memberStr.String != "" {
            p.Members = strings.Split(memberStr.String, ",")
        }

        // Parse Permissions
        if permStr.Valid && permStr.String != "" {
             perms := strings.Split(permStr.String, "|")
             for _, permRaw := range perms {
                 if permRaw == "" { continue }
                 parts := strings.Split(permRaw, ":")
                 if len(parts) >= 4 {
                     p.Permissions = append(p.Permissions, models.Permission{
                         State: parts[0],
                         Permission: parts[1],
                         SubEntityName: parts[2], // Major ID name
                         ClassDesc: parts[3],
                     })
                 }
             }
        }

		info.ServerPrincipals = append(info.ServerPrincipals, p)
	}
	return nil
}

func (c *MSSQLCollector) collectDatabases(ctx context.Context, db *sql.DB, info *models.MSSQLServerInfo) error {
    rows, err := db.QueryContext(ctx, QueryDatabases)
    if err != nil { return err }
    defer rows.Close()

    for rows.Next() {
        var d models.Database
        var ownerSid []byte
        var createDate sql.NullString
        var ownerName sql.NullString

        if err := rows.Scan(
            &d.Name, &d.DatabaseID, &createDate, &d.TRUSTWORTHY, &d.IsAccessible, // is_broker/encrypted mapped to accessible placeholder
            &d.IsAccessible, // is_read_only mapped to accessible placeholder
            &ownerName, &ownerSid,
        ); err != nil {
            // Some databases might throw errors or have different schemas, handle gracefully
            continue
        }

        d.OwnerLoginName = ownerName.String
        d.ObjectIdentifier = fmt.Sprintf("%s-%s", info.Name, d.Name)
        info.Databases = append(info.Databases, d)
    }
    return nil
}

func (c *MSSQLCollector) collectDatabasePrincipals(ctx context.Context, db *sql.DB, dbInfo *models.Database) error {
    // Switch context to database
    // Escape closing bracket for safety
    safeDbName := strings.ReplaceAll(dbInfo.Name, "]", "]]")
    _, err := db.ExecContext(ctx, fmt.Sprintf("USE [%s]", safeDbName))
    if err != nil { return err }

    rows, err := db.QueryContext(ctx, QueryDatabasePrincipals)
    if err != nil { return err }
    defer rows.Close()

    for rows.Next() {
        var p models.DatabasePrincipal
        var sid []byte
        var memberStr, memberOfStr, permStr sql.NullString
        var createDate, modifyDate, defSchema, svrLogin sql.NullString
        var owningId sql.NullInt64

        if err := rows.Scan(
            &p.Name, &p.PrincipalID, &p.TypeDescription, &createDate, &modifyDate, &defSchema, &p.IsFixedRole,
            &sid, &owningId,
            &memberStr, &memberOfStr, &permStr,
            &svrLogin,
        ); err != nil {
            continue
        }

        p.CreateDate = createDate.String
        p.ModifyDate = modifyDate.String
        p.DefaultSchemaName = defSchema.String
        p.SecurityIdentifier = fmt.Sprintf("%x", sid)
        p.ObjectIdentifier = fmt.Sprintf("%s-%s-%d", dbInfo.Name, p.Name, p.PrincipalID)

        // Parse permissions similarly to server principals
        if permStr.Valid && permStr.String != "" {
             perms := strings.Split(permStr.String, "|")
             for _, permRaw := range perms {
                 if permRaw == "" { continue }
                 parts := strings.Split(permRaw, ":")
                 if len(parts) >= 4 {
                     p.Permissions = append(p.Permissions, models.Permission{
                         State: parts[0],
                         Permission: parts[1],
                         SubEntityName: parts[2],
                         ClassDesc: parts[3],
                     })
                 }
             }
        }

        dbInfo.DatabasePrincipals = append(dbInfo.DatabasePrincipals, p)
    }
    return nil
}

func (c *MSSQLCollector) collectCredentials(ctx context.Context, db *sql.DB, info *models.MSSQLServerInfo) error {
    rows, err := db.QueryContext(ctx, QueryCredentials)
    if err != nil { return err }
    defer rows.Close()

    for rows.Next() {
        var cred models.Credential
        var createDate, modifyDate sql.NullString

        if err := rows.Scan(&cred.CredentialId, &cred.CredentialName, &cred.CredentialIdentity, &createDate, &modifyDate); err != nil {
            continue
        }
        cred.CreateDate = createDate.String
        cred.ModifyDate = modifyDate.String

        info.Credentials = append(info.Credentials, cred)
    }
    return nil
}
