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
	Id         string                 `json:"id"`
	Kinds      []string               `json:"kinds"`
	Properties map[string]interface{} `json:"properties"`
    Label      string                 `json:"label,omitempty"`
}

type Edge struct {
	Start      EdgeEndpoint           `json:"start"`
	End        EdgeEndpoint           `json:"end"`
	Kind       string                 `json:"kind"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type EdgeEndpoint struct {
	Value string `json:"value"`
}

// Internal MSSQL Data Models

type MSSQLServerInfo struct {
	Name                                    string
	ObjectIdentifier                        string
    HostSID                                 string
    HostDN                                  string
    HostName                                string
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
	ObjectIdentifier         string
    SecurityIdentifier       string
	TypeDescription          string
	IsDisabled               string
    IsFixedRole              string
	IsActiveDirectoryPrincipal string
	CreateDate               string
	ModifyDate               string
	DefaultDatabaseName      string
    SQLServerName            string
    SQLServerID              string
    OwningPrincipalID        int
    OwningObjectIdentifier   string
	MemberOf                 []ServerPrincipal
    Members                  []string
	Permissions              []Permission
    HasCredential            *Credential
}

type Database struct {
	Name                      string
	DatabaseID                int
	ObjectIdentifier          string
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
    IsFixedRole              string
	CreateDate               string
	ModifyDate               string
	DefaultSchemaName        string
    SQLServerName            string
	MemberOf                 []DatabasePrincipal
    Members                  []string
	Permissions              []Permission
    OwningPrincipalID        int
    OwningObjectIdentifier   string
    ServerLogin              *ServerPrincipal
}

type Permission struct {
	Permission             string
	State                  string
	ClassDesc              string
	SubEntityName          string
	PermissionName         string
    TargetObjectIdentifier string
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
    ResolvedPrincipal  *ServiceAccount
    ResolvedSID        string
    ResolvedType       string
    Database           string
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
    Principal *ServerPrincipal
    Members   []ServiceAccount
}
