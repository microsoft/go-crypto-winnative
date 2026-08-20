//go:build !386
// +build !386

package bcrypt

// https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
type AUTHENTICATED_CIPHER_MODE_INFO struct {
	Size           uint32
	InfoVersion    uint32
	Nonce          *byte
	NonceSize      uint32
	AuthData       *byte
	AuthDataSize   uint32
	Tag            *byte
	TagSize        uint32
	MacContext     *byte
	MacContextSize uint32
	AADSize        uint32
	DataSize       uint64
	Flags          uint32
}
