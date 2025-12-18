package models

type PrincipalResolver interface {
    Resolve(name string) (string, string, string, error) // Returns SID, DN, Type, error
}
