package converter

import (
	"strings"

	"github.com/SpecterOps/MSSQLHound/pkg/models"
)

func (c *Converter) addServiceAccountNodes(server *models.MSSQLServerInfo) {
	for _, sa := range server.ServiceAccounts {
		if sa.Name == "" {
			continue
		}

		id := sa.Name
		if sa.SID != "" {
			id = sa.SID
		}

		// Add User Node (or Computer if it ends in $)
		kinds := []string{"User", "Base"}
		if strings.HasSuffix(sa.Name, "$") {
			kinds = []string{"Computer", "Base"}
		}

		node := models.Node{
			Id:    id,
			Kinds: kinds,
			Properties: map[string]interface{}{
				"name":           sa.Name,
				"serviceAccount": true,
			},
			Label: sa.Name,
		}
		c.addNode(node)

		// Edge: ServiceAccount -> MSSQL_ServiceAccountFor -> Server
		c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
			id,
			server.ObjectIdentifier,
			"MSSQL_ServiceAccountFor",
			map[string]interface{}{
				"traversable": false,
				"general":     sa.Name + " is the service account for the SQL Server instance.",
			},
		))
	}
}
