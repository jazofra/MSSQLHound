
package collector

import (
    "context"
    "database/sql"
    "fmt"
    "github.com/SpecterOps/MSSQLHound/pkg/models"
)

func (c *MSSQLCollector) collectProxyAccounts(ctx context.Context, db *sql.DB, info *models.MSSQLServerInfo) error {
    rows, err := db.QueryContext(ctx, QueryProxyAccounts)
    if err != nil { return err }
    defer rows.Close()

    for rows.Next() {
        var p models.ProxyAccount
        var proxyId, credId int
        var desc, subsys, authPrincipals sql.NullString

        if err := rows.Scan(
            &proxyId, &p.ProxyName, &credId, &p.CredentialName, &p.CredentialIdentity, &p.Enabled,
            &desc, &subsys, &authPrincipals,
        ); err != nil {
            continue
        }

        p.ProxyId = fmt.Sprintf("%d", proxyId)
        p.CredentialId = fmt.Sprintf("%d", credId)
        p.Description = desc.String
        p.Subsystems = subsys.String
        p.AuthorizedPrincipals = authPrincipals.String

        // Resolve SID for CredentialIdentity?
        // PS1 does `Resolve-DomainPrincipal $credentialIdentity`.
        // We can use `utils.ConvertSidToSddl` if we had the SID, but we only have the name here.
        // We will store the name and let Converter try to link or just store properties.
        // Wait, PS1 resolves it to check if it's a domain principal.
        // We can do that in Converter if we have a way to resolve names, OR we rely on `ResolvedSID` being empty if we can't resolve.
        // For now, we populate the struct.

        info.ProxyAccounts = append(info.ProxyAccounts, p)
    }
    return nil
}
