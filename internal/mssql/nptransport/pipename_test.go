package nptransport

import (
	"slices"
	"testing"
)

func TestCandidates(t *testing.T) {
	tests := []struct {
		name     string
		instance string
		want     []string
	}{
		{
			name:     "empty instance tries default then WID",
			instance: "",
			want:     []string{`sql\query`, `MICROSOFT##WID\tsql\query`},
		},
		{
			name:     "explicit MSSQLSERVER behaves like the default instance",
			instance: "MSSQLSERVER",
			want:     []string{`sql\query`, `MICROSOFT##WID\tsql\query`},
		},
		{
			name:     "default instance name is case insensitive",
			instance: "mssqlserver",
			want:     []string{`sql\query`, `MICROSOFT##WID\tsql\query`},
		},
		{
			name:     "named instance uses the MSSQL$ prefix",
			instance: "SQLEXPRESS",
			want:     []string{`MSSQL$SQLEXPRESS\sql\query`},
		},
		{
			name:     "named instance is uppercased",
			instance: "sqlexpress",
			want:     []string{`MSSQL$SQLEXPRESS\sql\query`},
		},
		{
			name:     "surrounding whitespace is ignored",
			instance: "  SQLEXPRESS  ",
			want:     []string{`MSSQL$SQLEXPRESS\sql\query`},
		},
		{
			name:     "WID uses tsql and drops the MSSQL$ prefix",
			instance: "MICROSOFT##WID",
			want:     []string{`MICROSOFT##WID\tsql\query`},
		},
		{
			name:     "legacy SSEE keeps the regular naming",
			instance: "MICROSOFT##SSEE",
			want:     []string{`MSSQL$MICROSOFT##SSEE\sql\query`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Candidates(tc.instance)
			if !slices.Equal(got, tc.want) {
				t.Errorf("Candidates(%q) = %v, want %v", tc.instance, got, tc.want)
			}
		})
	}
}

// TestCandidatesWIDOnlyWhenUnspecified pins the discovery rule: we only go
// looking for a Windows Internal Database when the caller did not name an
// instance. Probing it for an explicitly named instance would be a guess.
func TestCandidatesWIDOnlyWhenUnspecified(t *testing.T) {
	if got := Candidates("SQLEXPRESS"); slices.Contains(got, `MICROSOFT##WID\tsql\query`) {
		t.Errorf("Candidates(%q) = %v, must not probe WID for a named instance", "SQLEXPRESS", got)
	}
}

func TestInstanceFromPipePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"default pipe has no instance", `sql\query`, ""},
		{"default pipe case insensitive", `SQL\QUERY`, ""},
		{"leading separator tolerated", `\sql\query`, ""},
		{"WID pipe", `MICROSOFT##WID\tsql\query`, "MICROSOFT##WID"},
		{"WID pipe case insensitive", `microsoft##wid\tsql\query`, "MICROSOFT##WID"},
		{"named instance", `MSSQL$SQLEXPRESS\sql\query`, "SQLEXPRESS"},
		{"named instance lowercase", `mssql$sqlexpress\sql\query`, "SQLEXPRESS"},
		{"legacy SSEE", `MSSQL$MICROSOFT##SSEE\sql\query`, "MICROSOFT##SSEE"},
		{"unrecognised custom path yields no instance", `some\custom\pipe`, ""},
		{"empty path", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := InstanceFromPipePath(tc.path); got != tc.want {
				t.Errorf("InstanceFromPipePath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestCandidatesRoundTrip checks the two functions agree: every path Candidates
// produces must map back to an instance name that regenerates the same path.
func TestCandidatesRoundTrip(t *testing.T) {
	for _, instance := range []string{"", "MSSQLSERVER", "SQLEXPRESS", "MICROSOFT##WID", "MICROSOFT##SSEE"} {
		for _, path := range Candidates(instance) {
			derived := InstanceFromPipePath(path)
			regenerated := Candidates(derived)
			if !slices.Contains(regenerated, path) {
				t.Errorf("path %q from instance %q derived instance %q, which regenerates %v (missing the original)",
					path, instance, derived, regenerated)
			}
		}
	}
}
