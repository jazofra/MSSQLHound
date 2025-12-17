
package converter

import (
    "strings"
    "github.com/SpecterOps/MSSQLHound/pkg/models"
)

func (c *Converter) addServiceAccountNodes(server *models.MSSQLServerInfo) {
    for _, sa := range server.ServiceAccounts {
        // Only valid if name is present
        if sa.Name == "" { continue }

        // Node ID: Usually we want SID, but SQL only gives Name.
        // PS1 resolves this. If we haven't resolved SID in Collector, we use Name as ID or skip.
        // Assuming Name is unique enough for now or we rely on 'MSSQL_ServiceAccountFor' logic.

        // Check if we have a better ID?
        id := sa.Name
        if sa.SID != "" {
            id = sa.SID
        }

        // Add User Node (or Computer if it ends in $)
        kinds := []string{"User"}
        if strings.HasSuffix(sa.Name, "$") {
            kinds = []string{"Computer"}
        }

        node := models.Node{
            Id: id,
            Kinds: kinds,
            Properties: map[string]interface{}{
                "name": sa.Name,
                "serviceAccount": true,
            },
            Label: sa.Name,
        }
        c.Output.Graph.Nodes = append(c.Output.Graph.Nodes, node)

        // Edge: ServiceAccount -> MSSQL_ServiceAccountFor -> Server
        c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
            Source: id,
            Target: server.ObjectIdentifier,
            Kind: "MSSQL_ServiceAccountFor",
        })
    }
}
