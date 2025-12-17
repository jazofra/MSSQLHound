
package converter

import (
    "strings"
    "github.com/SpecterOps/MSSQLHound/pkg/models"
)

func findCredentialById(server *models.MSSQLServerInfo, id string) *models.Credential {
    for _, c := range server.Credentials {
        if c.CredentialId == id {
            return &c
        }
    }
    return nil
}

func (c *Converter) processProxyAccounts(server *models.MSSQLServerInfo) {
    for _, proxy := range server.ProxyAccounts {
        // Find the Credential
        cred := findCredentialById(server, proxy.CredentialId)
        if cred != nil {
             // Edge: MSSQL_HasProxyCred (Principal -> Credential)
             // But wait, the edge is usually from the Principal authorized to use the proxy -> Credential Identity?
             // PS1:
             // Foreach authorized principal:
             // Add-Edge -Source Principal -Target CredentialSID -Kind MSSQL_HasProxyCred

             if proxy.AuthorizedPrincipals != "" {
                 principals := strings.Split(proxy.AuthorizedPrincipals, ",")
                 for _, pName := range principals {
                     pName = strings.TrimSpace(pName)
                     principal := findServerPrincipalByName(server, pName)
                     if principal != nil {
                         // Target is the Credential Identity (AD User)
                         targetId := cred.CredentialIdentity

                         // Create node for target if needed (covered by HasMappedCred usually, but safer to add)
                         // ...

                         c.Output.Graph.Edges = append(c.Output.Graph.Edges, models.Edge{
                             Source: principal.ObjectIdentifier,
                             Target: targetId,
                             Kind: "MSSQL_HasProxyCred",
                             Properties: map[string]interface{}{
                                 "proxyName": proxy.ProxyName,
                             },
                         })
                     }
                 }
             }
        }
    }
}
