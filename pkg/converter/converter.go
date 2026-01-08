package converter

import (
	"strings"

	"github.com/SpecterOps/MSSQLHound/pkg/models"
)

// Converter handles the transformation of MSSQL info to BloodHound Graph
type Converter struct {
	Output    *models.BloodHoundOutput
	nodeIndex map[string]bool // Track existing nodes to prevent duplicates
}

func NewConverter() *Converter {
	return &Converter{
		Output: &models.BloodHoundOutput{
			Graph: models.Graph{
				Nodes: []models.Node{},
				Edges: []models.Edge{},
			},
		},
		nodeIndex: make(map[string]bool),
	}
}

// newEdge creates a properly formatted edge for OpenGraph
func newEdge(source, target, kind string, properties map[string]interface{}) models.Edge {
	return models.Edge{
		Start:      models.EdgeEndpoint{Value: source},
		End:        models.EdgeEndpoint{Value: target},
		Kind:       kind,
		Properties: properties,
	}
}

// addNode adds a node only if it doesn't already exist
func (c *Converter) addNode(node models.Node) {
	if !c.nodeIndex[node.Id] {
		c.nodeIndex[node.Id] = true
		c.Output.Graph.Nodes = append(c.Output.Graph.Nodes, node)
	}
}

// Convert processes a single server info object and appends to the graph
func (c *Converter) Convert(server *models.MSSQLServerInfo) {
	// 0. Create Host Node (Computer) and Link to Server
	c.addHostNode(server)

	// 1. Create Server Node
	c.addServerNode(server)

	// 2. Create Server Principal Nodes & Edges
	for _, p := range server.ServerPrincipals {
		c.addServerPrincipalNode(server, &p)
	}

	// 3. Create Database Nodes
	for _, db := range server.Databases {
		c.addDatabaseNode(server, &db)

		// 4. Create Database Principal Nodes & Edges
		for _, dbp := range db.DatabasePrincipals {
			c.addDatabasePrincipalNode(server, &db, &dbp)
		}
	}

	// 5. Service Accounts
	c.addServiceAccountNodes(server)

	// 6. Linked Servers
	c.processLinkedServers(server)

	// 7. Proxy Accounts
	c.processProxyAccounts(server)

	// 8. Process Edges (Permissions and Relationships)
	c.processServerPermissions(server)
	for _, db := range server.Databases {
		c.processDatabasePermissions(server, &db)
		c.processTrustworthy(server, &db)
	}
}

func (c *Converter) addHostNode(server *models.MSSQLServerInfo) {
	if server.HostSID != "" {
		// Get domain from HostDN if available
		domain := extractDomainFromDN(server.HostDN)
		samAccountName := extractSAMAccountName(server.HostName)
		dnsHostName := server.HostName

		// Create Computer Node
		c.addNode(models.Node{
			Id:    server.HostSID,
			Kinds: []string{"Computer", "Base"},
			Properties: map[string]interface{}{
				"name":               server.HostName,
				"distinguishedname":  server.HostDN,
				"objectid":           server.HostSID,
				"domain":             domain,
				"isDomainPrincipal":  server.HostDN != "",
				"SID":                server.HostSID,
				"DNSHostName":        dnsHostName,
				"SAMAccountName":     samAccountName,
				"isEnabled":          true,
			},
			Label: server.HostName,
		})

		// MSSQL_HostFor: Host -> Server (with proper edge properties)
		c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
			server.HostSID,
			server.ObjectIdentifier,
			"MSSQL_HostFor",
			map[string]interface{}{
				"traversable": true,
				"general":     "The computer hosts the target SQL Server instance " + server.Name + ".",
				"windowsAbuse": `With admin access to the host, you can access the SQL instance: 
If the SQL instance is running as a built-in account (Local System, Local Service, or Network Service), it can be accessed with a SYSTEM context with sqlcmd. 
If the SQL instance is running in a domain service account context, the cleartext credentials can be dumped from LSA secrets with mimikatz sekurlsa::logonpasswords, then they can be used to request a service ticket for a domain account with admin access to the SQL instance. 
If there are no domain DBAs, it is still possible to start the instance in single-user mode, which allows any member of the computer's local Administrators group to connect as a sysadmin. WARNING: This is disruptive, possibly destructive, and will cause the database to become unavailable to other users while in single-user mode. It is not recommended.`,
				"linuxAbuse": "If you have root access to the host, you can access SQL Server by manipulating the service or accessing database files directly.",
				"opsec":      "Host access allows reading memory, modifying binaries, and accessing database files directly.",
				"references": "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions\n- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/start-sql-server-in-single-user-mode",
			},
		))

		// MSSQL_ExecuteOnHost: Server -> Host (control of server allows OS command execution)
		c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
			server.ObjectIdentifier,
			server.HostSID,
			"MSSQL_ExecuteOnHost",
			map[string]interface{}{
				"traversable": true,
				"general":     "Control of a SQL Server instance allows xp_cmdshell or other OS command execution capabilities to be used to access the host computer in the context of the account running the SQL server.",
				"windowsAbuse": "Enable and use xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'; ",
				"linuxAbuse":   "Enable and use xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'; ",
				"opsec":        "xp_cmdshell configuration option changes are logged in SQL Server error logs. View the log by executing: EXEC sp_readerrorlog 0, 1, 'xp_cmdshell'; ",
				"references":   "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql",
			},
		))
	}
}

func (c *Converter) addServerNode(server *models.MSSQLServerInfo) {
	// Build list of database names
	databases := []string{}
	for _, db := range server.Databases {
		databases = append(databases, db.Name)
	}

	// Build list of linked server names
	linkedToServers := []string{}
	for _, ls := range server.LinkedServers {
		linkedToServers = append(linkedToServers, ls.Name)
	}

	node := models.Node{
		Id:    server.ObjectIdentifier,
		Kinds: []string{"MSSQL_Server"},
		Properties: map[string]interface{}{
			"name":                                    server.Name,
			"instanceName":                            server.InstanceName,
			"port":                                    server.Port,
			"version":                                 server.Version,
			"isMixedModeAuthEnabled":                  server.IsMixedModeAuthEnabled,
			"databases":                               databases,
			"linkedToServers":                         linkedToServers,
			"servicePrincipalNames":                   server.ServicePrincipalNames,
			"domainPrincipalsWithSysadmin":            server.DomainPrincipalsWithSysadmin,
			"domainPrincipalsWithSecurityadmin":       server.DomainPrincipalsWithSecurityadmin,
			"domainPrincipalsWithControlServer":       server.DomainPrincipalsWithControlServer,
			"domainPrincipalsWithImpersonateAnyLogin": server.DomainPrincipalsWithImpersonateAnyLogin,
		},
		Label: server.Name,
	}
	c.addNode(node)
}

func (c *Converter) addServerPrincipalNode(server *models.MSSQLServerInfo, p *models.ServerPrincipal) {
	isRole := strings.Contains(p.TypeDescription, "ROLE")
	kinds := []string{}
	if isRole {
		kinds = append(kinds, "MSSQL_ServerRole")
	} else {
		kinds = append(kinds, "MSSQL_Login")
	}

	// Build memberOfRoles list
	memberOfRoles := []string{}
	for _, role := range p.MemberOf {
		memberOfRoles = append(memberOfRoles, role.Name)
	}

	// Build databaseUsers list (users mapped from this login)
	databaseUsers := []string{}
	for _, db := range server.Databases {
		for _, dbp := range db.DatabasePrincipals {
			if dbp.ServerLogin != nil && dbp.ServerLogin.Name == p.Name {
				databaseUsers = append(databaseUsers, dbp.Name+"@"+db.Name)
			}
		}
	}

	// Build explicitPermissions list
	explicitPermissions := []string{}
	for _, perm := range p.Permissions {
		if perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION" {
			explicitPermissions = append(explicitPermissions, perm.Permission)
		}
	}

	// Determine if AD principal
	isADPrincipal := strings.Contains(p.TypeDescription, "WINDOWS") || p.IsActiveDirectoryPrincipal == "1"

	// Build properties based on type (Login vs Role)
	props := map[string]interface{}{
		"name":       p.Name,
		"principalId": p.PrincipalID,
		"SQLServer":  server.Name,
		"createDate": p.CreateDate,
		"modifyDate": p.ModifyDate,
	}

	if isRole {
		props["isFixedRole"] = p.IsFixedRole == "1"
	} else {
		props["type"] = p.TypeDescription
		props["disabled"] = p.IsDisabled == "1"
		props["defaultDatabase"] = p.DefaultDatabaseName
		props["memberOfRoles"] = memberOfRoles
		props["databaseUsers"] = databaseUsers
		props["explicitPermissions"] = explicitPermissions
		props["isActiveDirectoryPrincipal"] = isADPrincipal
	}

	node := models.Node{
		Id:         p.ObjectIdentifier,
		Kinds:      kinds,
		Properties: props,
		Label:      p.Name,
	}
	c.addNode(node)

	// Membership Edges
	if len(p.Members) > 0 {
		for _, memberName := range p.Members {
			memberPrincipal := findServerPrincipalByName(server, memberName)
			if memberPrincipal != nil {
				c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
					memberPrincipal.ObjectIdentifier,
					p.ObjectIdentifier,
					"MSSQL_MemberOf",
					map[string]interface{}{
						"traversable": true,
						"general":     memberName + " is a member of the " + p.Name + " role.",
					},
				))
			}
		}
	}

	// MSSQL_HasMappedCred (Server Principal -> Credential)
	if p.HasCredential != nil {
		cred := findCredentialById(server, p.HasCredential.CredentialId)
		if cred != nil {
			targetId := cred.CredentialIdentity
			c.addNode(models.Node{
				Id:    targetId,
				Kinds: []string{"User", "Base"},
				Properties: map[string]interface{}{
					"name": cred.CredentialIdentity,
				},
				Label: cred.CredentialIdentity,
			})

			c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
				p.ObjectIdentifier,
				targetId,
				"MSSQL_HasMappedCred",
				map[string]interface{}{
					"traversable": false,
					"general":     "The login has a mapped credential for " + cred.CredentialIdentity + ".",
				},
			))
		}
	}

	// MSSQL_HasLogin (AD Principal -> MSSQL Login)
	if strings.Contains(p.TypeDescription, "WINDOWS") && p.SecurityIdentifier != "" {
		adNodeId := p.SecurityIdentifier
		adKinds := []string{"Base", "User"}
		if strings.Contains(p.TypeDescription, "GROUP") {
			adKinds = []string{"Base", "Group"}
		} else if strings.Contains(p.Name, "$") {
			adKinds = []string{"Base", "Computer"}
		}

		c.addNode(models.Node{
			Id:    adNodeId,
			Kinds: adKinds,
			Properties: map[string]interface{}{
				"name":                       p.Name,
				"objectid":                   adNodeId,
				"isActiveDirectoryPrincipal": true,
			},
			Label: p.Name,
		})

		c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
			adNodeId,
			p.ObjectIdentifier,
			"MSSQL_HasLogin",
			map[string]interface{}{
				"traversable": true,
				"general":     "The AD principal " + p.Name + " has a login on the SQL Server.",
			},
		))
	}
}

func findServerPrincipalByName(server *models.MSSQLServerInfo, name string) *models.ServerPrincipal {
	for _, p := range server.ServerPrincipals {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

func (c *Converter) addDatabaseNode(server *models.MSSQLServerInfo, db *models.Database) {
	node := models.Node{
		Id:    db.ObjectIdentifier,
		Kinds: []string{"MSSQL_Database"},
		Properties: map[string]interface{}{
			"name":          db.Name,
			"isTrustworthy": db.TRUSTWORTHY,
			"SQLServer":     server.Name,
		},
		Label: db.Name,
	}
	c.addNode(node)

	// Server -> Contains -> Database
	c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
		server.ObjectIdentifier,
		db.ObjectIdentifier,
		"MSSQL_Contains",
		map[string]interface{}{
			"traversable": false,
			"general":     "The SQL Server instance contains the database " + db.Name + ".",
		},
	))
}

func (c *Converter) addDatabasePrincipalNode(server *models.MSSQLServerInfo, db *models.Database, p *models.DatabasePrincipal) {
	kinds := []string{}
	isRole := strings.Contains(p.TypeDescription, "ROLE")
	if isRole {
		kinds = append(kinds, "MSSQL_DatabaseRole")
	} else {
		kinds = append(kinds, "MSSQL_DatabaseUser")
	}

	// Build memberOfRoles list
	memberOfRoles := []string{}
	for _, role := range p.MemberOf {
		memberOfRoles = append(memberOfRoles, role.Name)
	}

	props := map[string]interface{}{
		"name":               p.Name,
		"principalId":        p.PrincipalID,
		"database":           db.Name,
		"SQLServer":          server.Name,
		"type":               p.TypeDescription,
		"createDate":         p.CreateDate,
		"modifyDate":         p.ModifyDate,
		"defaultSchema":      p.DefaultSchemaName,
		"memberOfRoles":      memberOfRoles,
		"SecurityIdentifier": p.SecurityIdentifier,
	}

	// Add isFixedRole for database roles
	if isRole {
		props["isFixedRole"] = p.IsFixedRole == "1"
	}

	node := models.Node{
		Id:         p.ObjectIdentifier,
		Kinds:      kinds,
		Properties: props,
		Label:      p.Name,
	}
	c.addNode(node)

	// Database -> Contains -> Principal
	c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
		db.ObjectIdentifier,
		p.ObjectIdentifier,
		"MSSQL_Contains",
		map[string]interface{}{
			"traversable": false,
			"general":     "The database contains the principal " + p.Name + ".",
		},
	))

	// Membership for Database Roles
	if len(p.Members) > 0 {
		for _, memberName := range p.Members {
			memberPrincipal := findDatabasePrincipalByName(db, memberName)
			if memberPrincipal != nil {
				c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
					memberPrincipal.ObjectIdentifier,
					p.ObjectIdentifier,
					"MSSQL_MemberOf",
					map[string]interface{}{
						"traversable": true,
						"general":     memberName + " is a member of the " + p.Name + " role.",
					},
				))
			}
		}
	}
}

func findDatabasePrincipalByName(db *models.Database, name string) *models.DatabasePrincipal {
	for _, p := range db.DatabasePrincipals {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

func (c *Converter) processServerPermissions(server *models.MSSQLServerInfo) {
	for _, p := range server.ServerPrincipals {
		for _, perm := range p.Permissions {
			if perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION" {
				withGrant := perm.State == "GRANT_WITH_GRANT_OPTION"

				switch perm.Permission {
				case "CONTROL SERVER":
					c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
						p.ObjectIdentifier,
						server.ObjectIdentifier,
						"MSSQL_ControlServer",
						map[string]interface{}{
							"traversable": true,
							"withGrant":   withGrant,
							"general":     "The principal has CONTROL SERVER permission, equivalent to sysadmin.",
						},
					))
				case "ALTER ANY LOGIN":
					c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
						p.ObjectIdentifier,
						server.ObjectIdentifier,
						"MSSQL_AlterAnyLogin",
						map[string]interface{}{
							"traversable": true,
							"withGrant":   withGrant,
							"general":     "The principal can alter any login on the server.",
						},
					))
				case "IMPERSONATE ANY LOGIN":
					c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
						p.ObjectIdentifier,
						server.ObjectIdentifier,
						"MSSQL_ImpersonateAnyLogin",
						map[string]interface{}{
							"traversable": true,
							"withGrant":   withGrant,
							"general":     "The principal can impersonate any login on the server.",
						},
					))
				}

				// IMPERSONATE on specific login
				if perm.Permission == "IMPERSONATE" && perm.ClassDesc == "SERVER_PRINCIPAL" {
					target := findServerPrincipalByName(server, perm.SubEntityName)
					if target != nil {
						c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
							p.ObjectIdentifier,
							target.ObjectIdentifier,
							"MSSQL_Impersonate",
							map[string]interface{}{
								"traversable": true,
								"withGrant":   withGrant,
								"general":     "The principal can impersonate " + target.Name + ".",
							},
						))
						c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
							p.ObjectIdentifier,
							target.ObjectIdentifier,
							"MSSQL_ExecuteAs",
							map[string]interface{}{
								"traversable": true,
								"withGrant":   withGrant,
								"general":     "The principal can execute as " + target.Name + ".",
							},
						))
					}
				}

				// ALTER on Server Role (AddMember)
				if perm.Permission == "ALTER" && perm.ClassDesc == "SERVER_ROLE" {
					target := findServerPrincipalByName(server, perm.SubEntityName)
					if target != nil {
						c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
							p.ObjectIdentifier,
							target.ObjectIdentifier,
							"MSSQL_AddMember",
							map[string]interface{}{
								"traversable": true,
								"withGrant":   withGrant,
								"general":     "The principal can add members to the " + target.Name + " role.",
							},
						))
					}
				}

				// TAKE OWNERSHIP
				if perm.Permission == "TAKE OWNERSHIP" && perm.ClassDesc == "SERVER_ROLE" {
					target := findServerPrincipalByName(server, perm.SubEntityName)
					if target != nil {
						c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
							p.ObjectIdentifier,
							target.ObjectIdentifier,
							"MSSQL_TakeOwnership",
							map[string]interface{}{
								"traversable": true,
								"withGrant":   withGrant,
								"general":     "The principal can take ownership of the " + target.Name + " role.",
							},
						))
					}
				}
			}
		}
	}
}

func (c *Converter) processDatabasePermissions(server *models.MSSQLServerInfo, db *models.Database) {
	for _, p := range db.DatabasePrincipals {
		for _, perm := range p.Permissions {
			if perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION" {
				withGrant := perm.State == "GRANT_WITH_GRANT_OPTION"

				// DB Level permissions
				if perm.ClassDesc == "DATABASE" {
					if perm.Permission == "CONTROL" {
						c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
							p.ObjectIdentifier,
							db.ObjectIdentifier,
							"MSSQL_ControlDB",
							map[string]interface{}{
								"traversable": true,
								"withGrant":   withGrant,
								"general":     "The principal has CONTROL permission on the database.",
							},
						))
					}
				}
			}
		}
	}
}

func findCredentialById(server *models.MSSQLServerInfo, credId string) *models.Credential {
	for _, c := range server.Credentials {
		if c.CredentialId == credId {
			return &c
		}
	}
	return nil
}

// extractDomainFromDN extracts the domain name from a distinguished name
// e.g., "CN=SQLSERVER01,OU=Servers,DC=contoso,DC=com" -> "CONTOSO.COM"
func extractDomainFromDN(dn string) string {
	if dn == "" {
		return ""
	}

	parts := strings.Split(dn, ",")
	var dcParts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			dcParts = append(dcParts, strings.ToUpper(strings.TrimPrefix(strings.ToUpper(part), "DC=")))
		}
	}

	if len(dcParts) > 0 {
		return strings.Join(dcParts, ".")
	}
	return ""
}

// extractSAMAccountName extracts the SAM account name from a hostname
// For computer accounts, this is typically the hostname with a $ suffix
func extractSAMAccountName(hostname string) string {
	if hostname == "" {
		return ""
	}

	// Extract just the hostname part (before first dot if FQDN)
	name := hostname
	if idx := strings.Index(hostname, "."); idx > 0 {
		name = hostname[:idx]
	}

	return strings.ToUpper(name) + "$"
}
