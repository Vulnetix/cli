package auth

// TODO: Implement system keyring integration using a library like go-keyring.
// For now, all credential storage is file-based (home or project directory).
//
// Planned interface:
//   SaveToKeyring(creds *Credentials) error
//   LoadFromKeyring(orgID string) (*Credentials, error)
//   RemoveFromKeyring(orgID string) error
