package state

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type LockStatus int

const (
	StatusLoggedOut LockStatus = iota
	StatusLocked
	StatusUnlocked
)

var (
	ErrLocked                  = errors.New("state: vault is locked")
	ErrLoggedOut               = errors.New("state: no active account")
	ErrCipherNotFound          = errors.New("state: cipher not found")
	ErrFolderNotFound          = errors.New("state: folder not found")
	ErrUnsupportedCipherFormat = errors.New("state: unsupported v2 sealed blob cipher format")
	ErrInvalidSecretStore      = errors.New("state: secret store is required")
	ErrReadOnlyCipher          = errors.New("state: item is read-only")
	ErrOrganizationKeyMissing  = errors.New("state: organization key unavailable")
	ErrAttachmentNotFound      = errors.New("state: attachment not found")
	ErrHiddenByOrganization    = errors.New("state: hidden by your organization")
	ErrUnsupportedUpload       = errors.New("state: server requested an unsupported attachment upload method")
)

type FilterCategory int

const (
	FilterAll FilterCategory = iota
	FilterFavorites
	FilterTrash
	FilterNoFolder
)

type SearchFilter struct {
	Category       FilterCategory
	FolderID       string
	OrganizationID string
	CollectionID   string
	Type           *api.CipherType
}

type CipherSummary struct {
	ID       string
	Type     api.CipherType
	FolderID *string
	Favorite bool
	Deleted  bool
	Name     string
	Subtitle string
	HasTOTP  bool
	Reprompt int
	URIs     []string

	OrganizationID *string
	CollectionIDs  []string
}

type Cipher struct {
	ID               string
	Type             api.CipherType
	FolderID         *string
	OrganizationID   *string
	Favorite         bool
	Reprompt         int
	Key              *string
	Name             string
	Notes            string
	RevisionDate     *time.Time
	CreationDate     *time.Time
	DeletedDate      *time.Time
	ArchivedDate     *time.Time
	Login            *Login
	SecureNote       *SecureNote
	Card             *Card
	Identity         *Identity
	SSHKey           *SSHKey
	Fields           []CustomField
	PasswordHistory  []PasswordHistoryEntry
	Attachments      []Attachment
	Data             json.RawMessage
	EncryptedFor     *string
	EncryptedByKeyID *string
	CollectionIDs    []string
	ReadOnly         bool
	HidePassword     bool
	Extra            map[string]json.RawMessage
}

type Login struct {
	Username             string
	Password             string
	TOTP                 string
	URIs                 []LoginURI
	PasswordRevisionDate *time.Time
}

type LoginURI struct {
	URI   string
	Match *int
}

type SecureNote struct {
	Type int
}

type Card struct {
	CardholderName string
	Brand          string
	Number         string
	ExpMonth       string
	ExpYear        string
	Code           string
}

type Identity struct {
	Title          string
	FirstName      string
	MiddleName     string
	LastName       string
	Address1       string
	Address2       string
	Address3       string
	City           string
	State          string
	PostalCode     string
	Country        string
	Company        string
	Email          string
	Phone          string
	SSN            string
	Username       string
	PassportNumber string
	LicenseNumber  string
}

type SSHKey struct {
	PrivateKey     string
	PublicKey      string
	KeyFingerprint string
}

type CustomField struct {
	Name     string
	Value    string
	Type     int
	LinkedID *int
}

type Attachment struct {
	ID       string
	URL      string
	FileName string
	Key      *string
	Size     int64
	SizeName string
	Extra    map[string]json.RawMessage
}

type PasswordHistoryEntry struct {
	Password     string
	LastUsedDate time.Time
}

type Folder struct {
	ID           string
	Name         string
	RevisionDate *time.Time
	Extra        map[string]json.RawMessage
}

type LoginRequest struct {
	ServerURL      string
	Email          string
	MasterPassword []byte

	TwoFactorProvider api.TwoFactorProvider
	TwoFactorCode     string
	RememberDevice    bool
}

type Organization struct {
	ID      string
	Name    string
	Type    int
	Enabled bool
}

type Collection struct {
	ID             string
	OrganizationID string
	Name           string
	ReadOnly       bool
	HidePasswords  bool
	Manage         bool
}

type VaultService interface {
	Status() LockStatus
	Login(ctx context.Context, req LoginRequest) error
	SendEmailTwoFactorCode(ctx context.Context, req LoginRequest) error
	UnlockWithPassword(ctx context.Context, masterPassword []byte) error
	UnlockWithUserKey(ctx context.Context, userKey *crypto.SymmetricKey) error
	EnableBiometricUnlock(secrets store.SecretStore) error
	DisableBiometricUnlock(secrets store.SecretStore) error
	Lock()
	Logout(ctx context.Context, secrets store.SecretStore) error

	SyncNow(ctx context.Context) error
	Search(query string, filter SearchFilter) []CipherSummary
	GetCipher(id string) (*Cipher, error)
	AllCiphers() []*Cipher
	SaveCipher(ctx context.Context, c *Cipher) (*Cipher, error)
	SoftDeleteCipher(ctx context.Context, id string) error
	RestoreCipher(ctx context.Context, id string) error
	HardDeleteCipher(ctx context.Context, id string) error
	Folders() []Folder
	SaveFolder(ctx context.Context, f *Folder) (*Folder, error)
	DeleteFolder(ctx context.Context, id string) error
	DownloadAttachment(ctx context.Context, cipherID, attachmentID string) ([]byte, string, error)
	UploadAttachment(ctx context.Context, cipherID, fileName string, plain []byte) (*Cipher, error)
	DeleteAttachment(ctx context.Context, cipherID, attachmentID string) (*Cipher, error)
	Organizations() []Organization
	Collections() []Collection
}
