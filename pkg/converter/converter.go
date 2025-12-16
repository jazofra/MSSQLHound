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

    // 5. Process Edges (Permissions)
    c.processServerPermissions(server)
    for _, db := range server.Databases {
        c.processDatabasePermissions(server, &db)
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
    // Add edges for members of this role (Role -> MemberOf -> Principal)
    // NOTE: In MSSQL, if A is a member of B, B CONTAINS A.
    // BUT the edge is usually A -> MemberOf -> B or B -> Contains -> A.
    // MSSQLHound.ps1 creates MSSQL_MemberOf edges from member to role.
    if len(p.Members) > 0 {
         for _, memberName := range p.Members {
             // We need to find the principal with this name to get its ID
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

                // Handle specific target object permissions
                // In PS1: Set-EdgeContext resolves the target object from perm.TargetObjectIdentifier or class
                // Here we need to map perm.SubEntityName back to an object ID.
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
