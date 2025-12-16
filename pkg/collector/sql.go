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
}

func NewMSSQLCollector(host string, port int, instance string, username string, password string, domain string, authType string) *MSSQLCollector {
	// Build connection string
	var connStr string
	if authType == "Windows" {
		connStr = fmt.Sprintf("server=%s;port=%d;integrated security=true;", host, port)
	} else {
		connStr = fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;", host, port, username, password)
	}

    // Instance handling (if using SQL Browser resolution, go-mssqldb handles 'server=host\instance')
    if instance != "" && instance != "MSSQLSERVER" {
        // If port is default 1433, might be ignored if instance name is provided for browser lookup
        // But if port is provided explicitly, use it.
        // For 'server=host\instance', do not specify port usually, unless necessary.
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
	}
}

func (c *MSSQLCollector) Collect(ctx context.Context) (*models.MSSQLServerInfo, error) {
	db, err := sql.Open("sqlserver", c.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection: %v", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to server %s: %v", c.Host, err)
	}

	info := &models.MSSQLServerInfo{
		InstanceName: c.InstanceName,
		Port:         c.Port,
	}

	// 1. Server Info
	if err := c.collectServerInfo(ctx, db, info); err != nil {
		// Log error but continue? Or fail hard?
		return nil, fmt.Errorf("collectServerInfo: %v", err)
	}
    // Set object identifier
    info.ObjectIdentifier = fmt.Sprintf("%s:%d", info.Name, c.Port) // Simple ID for now, PS1 uses complex SID resolution

	// 2. Server Principals
	if err := c.collectServerPrincipals(ctx, db, info); err != nil {
		return nil, fmt.Errorf("collectServerPrincipals: %v", err)
	}

	// 3. Databases
	if err := c.collectDatabases(ctx, db, info); err != nil {
		return nil, fmt.Errorf("collectDatabases: %v", err)
	}

    // 4. Database Principals (Loop through DBs)
    for i := range info.Databases {
        if err := c.collectDatabasePrincipals(ctx, db, &info.Databases[i]); err != nil {
            // Log warning, continue
             // fmt.Printf("Warning: Failed to collect principals for DB %s: %v\n", info.Databases[i].Name, err)
        }
    }

	// 5. Credentials
	if err := c.collectCredentials(ctx, db, info); err != nil {
        // Warning
    }

    // 6. Linked Servers
    if err := c.collectLinkedServers(ctx, db, info); err != nil {
        // Warning
    }

	return info, nil
}

func (c *MSSQLCollector) collectServerInfo(ctx context.Context, db *sql.DB, info *models.MSSQLServerInfo) error {
	row := db.QueryRowContext(ctx, QueryServerInfo)

    var serverName, machineName, instanceName, prodVer, svcName, svcAccount, authMode, extProt string
	var isClustered, isHadr, crossDb, xpCmd, clr, ole, showAdv, scanStart, remAdmin, adHoc, trust int
    // Scan all cols
    // Note: Null handling is important.

    // Using nullable types or sql.NullString is safer, but for brevity assuming non-null for system views usually
    err := row.Scan(
        &serverName, &machineName, &instanceName, &prodVer, &isClustered, &isHadr,
        &svcName, &svcAccount,
        &crossDb, &xpCmd, &clr, &ole, &showAdv, &scanStart, &remAdmin, &adHoc, &trust,
        &authMode, &extProt,
    )
    if err != nil {
        return err
    }

    info.Name = serverName
    info.Version = prodVer
    info.IsMixedModeAuthEnabled = (authMode == "SQL Server and Windows Authentication")

    // Configurations
    info.CrossDbOwnershipChaining = crossDb
    info.XpCmdshell = xpCmd
    info.ClrEnabled = clr
    info.OleAutomationProcedures = ole
    info.ShowAdvancedOptions = showAdv
    info.ScanForStartupProcs = scanStart
    info.RemoteAdminConnections = remAdmin
    info.AdHocDistributedQueries = adHoc
    info.Trustworthy = trust

    // Service Account
    info.ServiceAccounts = []models.ServiceAccount{{Name: svcAccount}}

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

		if err := rows.Scan(
            &p.Name, &p.PrincipalID, &p.TypeDescription, &p.IsDisabled, &p.IsFixedRole,
            &createDate, &modifyDate, &defaultDB, &sid,
            &memberStr, &memberOfStr, &permStr,
        ); err != nil {
			return err
		}

        // Use SDDL format for SIDs
        sddl := utils.ConvertSidToSddl(sid)
        p.ObjectIdentifier = sddl
        p.SecurityIdentifier = sddl

        p.CreateDate = createDate.String
        p.ModifyDate = modifyDate.String
        p.DefaultDatabaseName = defaultDB.String
        p.SQLServerName = info.Name

        // Parse Members
        if memberStr.Valid && memberStr.String != "" {
            p.Members = strings.Split(memberStr.String, ",")
        }

        // Parse MemberOf (Need to resolve to Objects later, for now just strings)
        // The model expects []ServerPrincipal, but here we just have names.
        // We will store names temporarily or handle linkage in the Converter phase.
        // For now, let's change the query or logic. The PS1 logic builds objects then links.
        // I'll leave the struct empty and handle it if needed or store metadata.

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
        d.ObjectIdentifier = fmt.Sprintf("%s-%s", info.Name, d.Name) // Simplified ID
        info.Databases = append(info.Databases, d)
    }
    return nil
}

func (c *MSSQLCollector) collectDatabasePrincipals(ctx context.Context, db *sql.DB, dbInfo *models.Database) error {
    // Switch context to database
    _, err := db.ExecContext(ctx, fmt.Sprintf("USE [%s]", dbInfo.Name))
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
