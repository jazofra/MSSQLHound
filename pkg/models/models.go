package models

// BloodHound JSON Structure
type BloodHoundOutput struct {
	Graph Graph `json:"graph"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Node struct {
	Id         string                 `json:"id"` // Ensure this is serialized as "objectid" if needed, but BH 4+ uses "id"?
                                              // Checking PS1: Add-Node uses -Id, but the output JSON property is likely "data" with "objectid"?
                                              // Wait, let's double check the PS1 output format.
	Kinds      []string               `json:"kinds"`
	Properties map[string]interface{} `json:"properties"`
    Label      string                 `json:"label,omitempty"` // Sometimes used, but usually Kinds is enough
}

type Edge struct {
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Kind       string                 `json:"kind"`
	Properties map[string]interface{} `json:"properties"`
}

// Internal MSSQL Data Models

type MSSQLServerInfo struct {
	Name                                    string
	ObjectIdentifier                        string
	InstanceName                            string
    Port                                    int
	Version                                 string
	ServiceAccounts                         []ServiceAccount
	ServicePrincipalNames                   []string
	DomainPrincipalsWithControlServer       []string
	DomainPrincipalsWithImpersonateAnyLogin []string
	DomainPrincipalsWithSecurityadmin       []string
	DomainPrincipalsWithSysadmin            []string
	IsAnyDomainPrincipalSysadmin            bool
    IsMixedModeAuthEnabled                  bool
    CrossDbOwnershipChaining                int
    XpCmdshell                              int
    ClrEnabled                              int
    OleAutomationProcedures                 int
    ShowAdvancedOptions                     int
    ScanForStartupProcs                     int
    RemoteAdminConnections                  int
    AdHocDistributedQueries                 int
    Trustworthy                             int
	ExtendedProtection                      string
	ForceEncryption                         int
	ServerPrincipals                        []ServerPrincipal
	Databases                               []Database
	LinkedServers                           []LinkedServer
	Credentials                             []Credential
    ProxyAccounts                           []ProxyAccount
    LocalGroupsWithLogins                   map[string]LocalGroupInfo
}

type ServiceAccount struct {
	Name              string
	ObjectIdentifier  string
	Type              string
	DistinguishedName string
	DNSHostName       string
	Domain            string
	IsDomainPrincipal bool
	Enabled           bool
	SamAccountName    string
	SID               string
	UserPrincipalName string
}

type ServerPrincipal struct {
	Name                     string
	PrincipalID              int
	ObjectIdentifier         string // SID or other unique ID
    SecurityIdentifier       string // SID
	TypeDescription          string
	IsDisabled               string // "1" or "0" in PS1
    IsFixedRole              string // "1" or "0"
	IsActiveDirectoryPrincipal string // "1" or "0"
	CreateDate               string
	ModifyDate               string
	DefaultDatabaseName      string
    SQLServerName            string
    SQLServerID              string
    OwningPrincipalID        int // For roles
    OwningObjectIdentifier   string
	MemberOf                 []ServerPrincipal // Roles this principal is a member of
    Members                  []string // Names of members
	Permissions              []Permission
    HasCredential            *Credential
}

type Database struct {
	Name                      string
	DatabaseID                int
	ObjectIdentifier          string // usually generated
	PrincipalID               int
	OwnerLoginName            string
	OwnerPrincipalID          int
    OwnerObjectIdentifier     string
	TRUSTWORTHY               bool
    IsAccessible              bool
	DatabasePrincipals        []DatabasePrincipal
    DatabaseScopedCredentials []Credential
}

type DatabasePrincipal struct {
	Name                     string
	PrincipalID              int
	ObjectIdentifier         string
    SecurityIdentifier       string
	TypeDescription          string
    IsFixedRole              string // "1" or "0"
	CreateDate               string
	ModifyDate               string
	DefaultSchemaName        string
    SQLServerName            string
	MemberOf                 []DatabasePrincipal // Roles this principal is a member of
    Members                  []string // Names of members
	Permissions              []Permission
    OwningPrincipalID        int
    OwningObjectIdentifier   string
    ServerLogin              *ServerPrincipal // Mapped login
}

type Permission struct {
	Permission             string
	State                  string
	ClassDesc              string
	SubEntityName          string
	PermissionName         string
    TargetObjectIdentifier string // Calculated target
}

type LinkedServer struct {
    Path                         string
    ServerID                     int
    Name                         string
    Product                      string
    Provider                     string
    DataSource                   string
    ProviderString               string
    Location                     string
    Cat                          string
    LocalLogin                   string
    RemoteLogin                  string
    IsRmtLogin                   bool
    IsRmtLoginImp                bool
    UsesImpersonation            bool
    RPCOut                       bool
    DataAccess                   bool
    ModifyDate                   string
    LinkedServer                 string
    SourceServer                 string
    ResolvedObjectIdentifier     string
    RemoteIsSysadmin             bool
    RemoteIsSecurityAdmin        bool
    RemoteHasControlServer       bool
    RemoteHasImpersonateAnyLogin bool
    RemoteCurrentLogin           string
    RemoteServerRoles            string
    RemoteIsMixedMode            bool
}

type Credential struct {
    CredentialId       string
    CredentialName     string
    CredentialIdentity string
    CreateDate         string
    ModifyDate         string
    IsDomainPrincipal  bool
    ResolvedPrincipal  *ServiceAccount // Reusing ServiceAccount struct for generic resolved principal
    ResolvedSID        string
    ResolvedType       string
    Database           string // For DB scoped credentials
}

type ProxyAccount struct {
    ProxyId              string
    ProxyName            string
    CredentialId         string
    CredentialName       string
    CredentialIdentity   string
    Enabled              bool
    Description          string
    Subsystems           string
    AuthorizedPrincipals string
    IsDomainPrincipal    bool
    ResolvedPrincipal    *ServiceAccount
    ResolvedSID          string
    ResolvedType         string
}

type LocalGroupInfo struct {
    Principal *ServerPrincipal // Reusing ServerPrincipal to store group details
    Members   []ServiceAccount // Reusing ServiceAccount for member details
}
