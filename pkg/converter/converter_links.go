package converter

import (
	"github.com/SpecterOps/MSSQLHound/pkg/models"
)

func (c *Converter) processLinkedServers(server *models.MSSQLServerInfo) {
	for _, link := range server.LinkedServers {
		if link.Name == "" {
			continue
		}

		// Target ID: We use the name or data source if available.
		targetId := link.Name
		if link.DataSource != "" {
			targetId = link.DataSource
		}

		// Add Linked Server Node (Partial info)
		c.addNode(models.Node{
			Id:    targetId,
			Kinds: []string{"MSSQL_Server"},
			Properties: map[string]interface{}{
				"name":               targetId,
				"isLinkedServerTarget": true,
				"provider":           link.Provider,
				"product":            link.Product,
			},
			Label: targetId,
		})

		// Edge: MSSQL_LinkedTo
		c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
			server.ObjectIdentifier,
			targetId,
			"MSSQL_LinkedTo",
			map[string]interface{}{
				"traversable": false,
				"provider":    link.Provider,
				"general":     "The server has a linked server connection to " + targetId + ".",
			},
		))
	}
}

func (c *Converter) processTrustworthy(server *models.MSSQLServerInfo, db *models.Database) {
	if db.TRUSTWORTHY {
		// MSSQL_IsTrustedBy: Database -> Server
		c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
			db.ObjectIdentifier,
			server.ObjectIdentifier,
			"MSSQL_IsTrustedBy",
			map[string]interface{}{
				"traversable": false,
				"general":     "The database " + db.Name + " has TRUSTWORTHY enabled.",
			},
		))

		// MSSQL_ExecuteAsOwner
		if db.OwnerLoginName != "" {
			owner := findServerPrincipalByName(server, db.OwnerLoginName)
			if owner != nil {
				c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
					db.ObjectIdentifier,
					server.ObjectIdentifier,
					"MSSQL_ExecuteAsOwner",
					map[string]interface{}{
						"traversable": true,
						"owner":       db.OwnerLoginName,
						"general":     "The trustworthy database is owned by " + db.OwnerLoginName + ", allowing privilege escalation if the owner has high privileges.",
					},
				))
			}
		}
	}
}
