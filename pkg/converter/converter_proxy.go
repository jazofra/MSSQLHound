package converter

import (
	"strings"

	"github.com/SpecterOps/MSSQLHound/pkg/models"
)

func (c *Converter) processProxyAccounts(server *models.MSSQLServerInfo) {
	for _, proxy := range server.ProxyAccounts {
		// Find the Credential
		cred := findCredentialById(server, proxy.CredentialId)
		if cred != nil {
			if proxy.AuthorizedPrincipals != "" {
				principals := strings.Split(proxy.AuthorizedPrincipals, ",")
				for _, pName := range principals {
					pName = strings.TrimSpace(pName)
					principal := findServerPrincipalByName(server, pName)
					if principal != nil {
						targetId := cred.CredentialIdentity

						// Create node for credential target if needed
						c.addNode(models.Node{
							Id:    targetId,
							Kinds: []string{"User", "Base"},
							Properties: map[string]interface{}{
								"name": cred.CredentialIdentity,
							},
							Label: cred.CredentialIdentity,
						})

						c.Output.Graph.Edges = append(c.Output.Graph.Edges, newEdge(
							principal.ObjectIdentifier,
							targetId,
							"MSSQL_HasProxyCred",
							map[string]interface{}{
								"traversable": false,
								"proxyName":   proxy.ProxyName,
								"general":     "The principal has access to proxy " + proxy.ProxyName + " using credential " + cred.CredentialIdentity + ".",
							},
						))
					}
				}
			}
		}
	}
}
