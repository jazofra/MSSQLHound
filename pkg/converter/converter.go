package converter

import (
	"strings"

	"github.com/SpecterOps/MSSQLHound/pkg/models"
)

// Converter handles the transformation of MSSQL info to BloodHound Graph
type Converter struct {
	Output *models.BloodHoundOutput
}

func NewConverter() *Converter {
	return &Converter{
		Output: &models.BloodHoundOutput{
			Graph: models.Graph{
				Nodes: []models.Node{},
				Edges: []models.Edge{},
			},
		},
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
        // Create Computer Node
        c.Output.Graph.Nodes = append(c.Output.Graph.Nodes, models.Node{
            Id: server.HostSID,
            Kinds: []string{"Computer", "Base"},
            Properties: map[string]interface{}{
                "name": server.HostName,
                "distinguishedname": server.HostDN,
                "objectid": server.HostSID,
            },
            Label: server.HostName,
        })

        // MSSQL_HostFor: Host -> Server
        c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
            Source: server.HostSID,
            Target: server.ObjectIdentifier,
            Kind: "MSSQL_HostFor",
        })

        // MSSQL_ExecuteOnHost: Server -> Host (Implicitly true for server instance)
        // Note: PS1 creates MSSQL_ExecuteOnHost? No, typically it's specific perms.
        // But the relationship implies code execution possibility.
        // Standard model: MSSQL_HostFor.
    }
}

func (c *Converter) addServerNode(server *models.MSSQLServerInfo) {
	node := models.Node{
		Id:    server.ObjectIdentifier,
		Kinds: []string{"MSSQL_Server"},
		Properties: map[string]interface{}{
			"name":            server.Name,
			"instanceName":    server.InstanceName,
			"port":            server.Port,
			"version":         server.Version,
            "isMixedModeAuthEnabled": server.IsMixedModeAuthEnabled,
		},
        Label: server.Name,
	}
	c.Output.Graph.Nodes = append(c.Output.Graph.Nodes, node)
}

func (c *Converter) addServerPrincipalNode(server *models.MSSQLServerInfo, p *models.ServerPrincipal) {
    kinds := []string{}
    if strings.Contains(p.TypeDescription, "ROLE") {
        kinds = append(kinds, "MSSQL_ServerRole")
    } else {
        kinds = append(kinds, "MSSQL_Login")
    }

    node := models.Node{
        Id: p.ObjectIdentifier, // Should be SID
        Kinds: kinds,
        Properties: map[string]interface{}{
            "name": p.Name,
            "principalId": p.PrincipalID,
            "type": p.TypeDescription,
            "isDisabled": p.IsDisabled == "1",
            "sqlServer": server.Name,
        },
        Label: p.Name,
    }
    c.Output.Graph.Nodes = append(c.Output.Graph.Nodes, node)

    // Membership Edges
    if len(p.Members) > 0 {
         for _, memberName := range p.Members {
             memberPrincipal := findServerPrincipalByName(server, memberName)
             if memberPrincipal != nil {
                 c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                     Source: memberPrincipal.ObjectIdentifier,
                     Target: p.ObjectIdentifier,
                     Kind: "MSSQL_MemberOf",
                 })
             }
         }
    }

    // MSSQL_HasMappedCred (Server Principal -> Credential)
    if p.HasCredential != nil {
        // Find the actual credential object
        cred := findCredentialById(server, p.HasCredential.CredentialId)
        if cred != nil {
             // Create Credential Node? Usually not a node in BH graph?
             // PS1 creates "Base" nodes for credentials.
             // We need to create a Node for the credential identity (the AD user it uses).
             // But Wait, `MSSQL_HasMappedCred` edge goes from Principal -> CredentialIdentity(SID).
             // We need to resolve the CredentialIdentity to SID.
             // PS1 does `Resolve-DomainPrincipal`. We don't have that easily here.
             // Best effort: Use the CredentialIdentity string as ID if no SID.

             targetId := cred.CredentialIdentity // Fallback
             // If we had resolved SID, use it.
             // Assuming we create a node for it.
             c.Output.Graph.Nodes = append(c.Output.Graph.Nodes, models.Node{
                 Id: targetId,
                 Kinds: []string{"User", "Base"}, // Guessing User
                 Properties: map[string]interface{}{
                     "name": cred.CredentialIdentity,
                 },
                 Label: cred.CredentialIdentity,
             })

             c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                 Source: p.ObjectIdentifier,
                 Target: targetId,
                 Kind: "MSSQL_HasMappedCred",
             })
        }
    }

    // MSSQL_HasLogin (AD Principal -> MSSQL Login)
    // If the principal is a WINDOWS_LOGIN or WINDOWS_GROUP, it maps to an AD object (User/Group/Computer)
    if strings.Contains(p.TypeDescription, "WINDOWS") && p.SecurityIdentifier != "" {
        // Create AD Node
        // We use the SID as the ID. BloodHound uses SID for AD nodes.
        adNodeId := p.SecurityIdentifier
        adKinds := []string{"Base", "User"} // Default to User
        if strings.Contains(p.TypeDescription, "GROUP") {
            adKinds = []string{"Base", "Group"}
        } else if strings.Contains(p.Name, "$") {
             adKinds = []string{"Base", "Computer"}
        }

        // Add the AD Node (if not exists logic handled by BH ingest usually, but we emit it)
        c.Output.Graph.Nodes = append(c.Output.Graph.Nodes, models.Node{
            Id: adNodeId,
            Kinds: adKinds,
            Properties: map[string]interface{}{
                "name": p.Name, // This usually includes DOMAIN\Name
                "objectid": adNodeId,
            },
            Label: p.Name,
        })

        // Add Edge
        c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
            Source: adNodeId,
            Target: p.ObjectIdentifier,
            Kind: "MSSQL_HasLogin",
        })
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
        Id: db.ObjectIdentifier,
        Kinds: []string{"MSSQL_Database"},
        Properties: map[string]interface{}{
            "name": db.Name,
            "isTrustworthy": db.TRUSTWORTHY,
            "sqlServer": server.Name,
        },
        Label: db.Name,
    }
    c.Output.Graph.Nodes = append(c.Output.Graph.Nodes, node)

    // Server -> Contains -> Database
    c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
        Source: server.ObjectIdentifier,
        Target: db.ObjectIdentifier,
        Kind: "MSSQL_Contains",
    })
}

func (c *Converter) addDatabasePrincipalNode(server *models.MSSQLServerInfo, db *models.Database, p *models.DatabasePrincipal) {
     kinds := []string{}
    if strings.Contains(p.TypeDescription, "ROLE") {
        kinds = append(kinds, "MSSQL_DatabaseRole")
    } else {
        kinds = append(kinds, "MSSQL_DatabaseUser")
    }

    node := models.Node{
        Id: p.ObjectIdentifier,
        Kinds: kinds,
        Properties: map[string]interface{}{
            "name": p.Name,
            "principalId": p.PrincipalID,
            "database": db.Name,
        },
        Label: p.Name,
    }
    c.Output.Graph.Nodes = append(c.Output.Graph.Nodes, node)

    // Database -> Contains -> Principal
    c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
        Source: db.ObjectIdentifier,
        Target: p.ObjectIdentifier,
        Kind: "MSSQL_Contains",
    })

    // Membership for Database Roles
    if len(p.Members) > 0 {
         for _, memberName := range p.Members {
             // Resolve member name to principal
             memberPrincipal := findDatabasePrincipalByName(db, memberName)
             if memberPrincipal != nil {
                 c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                     Source: memberPrincipal.ObjectIdentifier,
                     Target: p.ObjectIdentifier,
                     Kind: "MSSQL_MemberOf",
                 })
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
                switch perm.Permission {
                case "CONTROL SERVER":
                    c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                        Source: p.ObjectIdentifier,
                        Target: server.ObjectIdentifier,
                        Kind: "MSSQL_ControlServer",
                    })
                case "ALTER ANY LOGIN":
                     c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                        Source: p.ObjectIdentifier,
                        Target: server.ObjectIdentifier,
                        Kind: "MSSQL_AlterAnyLogin",
                    })
                     // Also generates MSSQL_ChangePassword to all non-sysadmin logins
                case "IMPERSONATE ANY LOGIN":
                     c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                        Source: p.ObjectIdentifier,
                        Target: server.ObjectIdentifier,
                        Kind: "MSSQL_ImpersonateAnyLogin",
                    })
                }

                // IMPERSONATE on specific login
                if perm.Permission == "IMPERSONATE" && perm.ClassDesc == "SERVER_PRINCIPAL" {
                    // Resolve target from SubEntityName
                     target := findServerPrincipalByName(server, perm.SubEntityName)
                     if target != nil {
                         c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                             Source: p.ObjectIdentifier,
                             Target: target.ObjectIdentifier,
                             Kind: "MSSQL_Impersonate",
                         })
                         c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                             Source: p.ObjectIdentifier,
                             Target: target.ObjectIdentifier,
                             Kind: "MSSQL_ExecuteAs",
                         })
                     }
                }

                // ALTER on Server Role (AddMember)
                if perm.Permission == "ALTER" && perm.ClassDesc == "SERVER_ROLE" {
                     target := findServerPrincipalByName(server, perm.SubEntityName)
                     if target != nil {
                         c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                             Source: p.ObjectIdentifier,
                             Target: target.ObjectIdentifier,
                             Kind: "MSSQL_AddMember",
                         })
                     }
                }

                // TAKE OWNERSHIP
                if perm.Permission == "TAKE OWNERSHIP" && perm.ClassDesc == "SERVER_ROLE" {
                     target := findServerPrincipalByName(server, perm.SubEntityName)
                     if target != nil {
                         c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                             Source: p.ObjectIdentifier,
                             Target: target.ObjectIdentifier,
                             Kind: "MSSQL_TakeOwnership",
                         })
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
                 // DB Level permissions
                 if perm.ClassDesc == "DATABASE" {
                     if perm.Permission == "CONTROL" {
                          c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                            Source: p.ObjectIdentifier,
                            Target: db.ObjectIdentifier,
                            Kind: "MSSQL_ControlDB",
                        })
                     }
                 }
            }
         }
    }
}
