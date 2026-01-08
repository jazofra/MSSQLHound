package collector

import (
    "context"
    "database/sql"
    "github.com/SpecterOps/MSSQLHound/pkg/models"
)

func (c *MSSQLCollector) collectLinkedServers(ctx context.Context, db *sql.DB, info *models.MSSQLServerInfo) error {
    rows, err := db.QueryContext(ctx, QueryLinkedServers)
    if err != nil { return err }
    defer rows.Close()

    for rows.Next() {
        var ls models.LinkedServer
        var srvName, provider, prod, dataSrc sql.NullString
        var isLinked int

        if err := rows.Scan(
            &srvName, &provider, &prod, &dataSrc, &isLinked,
        ); err != nil {
            continue
        }

        ls.Name = srvName.String
        ls.Provider = provider.String
        ls.Product = prod.String
        ls.DataSource = dataSrc.String

        info.LinkedServers = append(info.LinkedServers, ls)
    }
    return nil
}
