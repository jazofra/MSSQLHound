package nptransport

import "strings"

// Pipe paths are given relative to the IPC$ share, which is how SMB clients open
// them: IPC$ is mounted and the pipe is opened as a file within it. The absolute
// form a user would recognise is \\HOST\pipe\<path>.
const (
	// defaultPipe serves the default instance (MSSQLSERVER).
	defaultPipe = `sql\query`

	// widPipe serves the Windows Internal Database on Server 2012 and later. Note
	// the two irregularities: the verb is "tsql", not "sql", and there is no
	// MSSQL$ prefix even though MICROSOFT##WID is a named instance.
	widPipe = `MICROSOFT##WID\tsql\query`

	// sseePipe serves the pre-2012 incarnation of the same idea (SQL Server 2005
	// Embedded Edition), which does use the regular MSSQL$ naming.
	sseePipe = `MSSQL$MICROSOFT##SSEE\sql\query`

	widInstance  = "MICROSOFT##WID"
	sseeInstance = "MICROSOFT##SSEE"

	// defaultInstance is the instance name SQL Server gives the default instance.
	defaultInstance = "MSSQLSERVER"
)

// Candidates returns the pipe paths to try for the given instance name, in order.
//
// Callers must advance to the next candidate only when the previous one reported
// that the pipe does not exist. Any other failure — access denied, a tree-connect
// error, an authentication failure — is terminal, because retrying it would just
// generate more failed logons against the host.
//
// When no instance is named we try the default instance first and then the
// Windows Internal Database. That second attempt is what lets WSUS and AD FS hosts
// be collected at all: WID has no TCP endpoint whatsoever, so it is invisible to
// every other code path in this tool.
func Candidates(instance string) []string {
	normalized := strings.ToUpper(strings.TrimSpace(instance))

	switch normalized {
	case "", defaultInstance:
		return []string{defaultPipe, widPipe}
	case widInstance:
		return []string{widPipe}
	case sseeInstance:
		return []string{sseePipe}
	default:
		// Pipe names are matched case-insensitively over SMB, so uppercasing is
		// cosmetic; it keeps us consistent with go-mssqldb, which uppercases the
		// instance name when matching SQL Browser replies.
		return []string{`MSSQL$` + normalized + `\` + defaultPipe}
	}
}

// InstanceFromPipePath recovers the SQL Server instance name that a pipe path
// belongs to, returning "" for the default instance.
//
// This matters for graph correctness rather than for connecting. When a host's
// default pipe is absent and we fall through to the WID pipe, we have reached a
// genuinely different SQL Server instance; filing it under the host's
// default-instance identity would silently overwrite or misattribute a node.
func InstanceFromPipePath(path string) string {
	p := strings.TrimPrefix(strings.TrimSpace(path), `\`)

	switch {
	case strings.EqualFold(p, defaultPipe):
		return ""
	case strings.EqualFold(p, widPipe):
		return widInstance
	}

	if rest, ok := cutPrefixFold(p, `MSSQL$`); ok {
		if idx := strings.Index(rest, `\`); idx > 0 {
			return strings.ToUpper(rest[:idx])
		}
	}

	// An unrecognised shape means the operator supplied a custom path via
	// --named-pipe-path. We cannot infer an instance name, and guessing one would
	// be worse than admitting we do not know.
	return ""
}

// cutPrefixFold is strings.CutPrefix with case-insensitive matching.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}
