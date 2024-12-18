package bcrypt

import (
	"fmt"
	"syscall"
	"unicode/utf16"
)

const (
	FORMAT_MESSAGE_FROM_HMODULE   = 2048
	FORMAT_MESSAGE_FROM_SYSTEM    = 4096
	FORMAT_MESSAGE_ARGUMENT_ARRAY = 8192

	LANG_ENGLISH       = 0x09
	SUBLANG_ENGLISH_US = 0x01
)

type NTStatus uint32

func (s NTStatus) Errno() syscall.Errno {
	return rtlNtStatusToDosErrorNoTeb(s)
}

func langID(pri, sub uint16) uint32 { return uint32(sub)<<10 | uint32(pri) }

func (s NTStatus) Error() string {
	b := make([]uint16, 300)
	n, err := FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_ARGUMENT_ARRAY, modntdll.Handle(), uint32(s), langID(LANG_ENGLISH, SUBLANG_ENGLISH_US), b, nil)
	if err != nil {
		return fmt.Sprintf("NTSTATUS 0x%08x", uint32(s))
	}
	// trim terminating \r and \n
	for ; n > 0 && (b[n-1] == '\n' || b[n-1] == '\r'); n-- {
	}
	return string(utf16.Decode(b[:n]))
}

// NT Native APIs
//sys	rtlNtStatusToDosErrorNoTeb(ntstatus NTStatus) (ret syscall.Errno) = ntdll.RtlNtStatusToDosErrorNoTeb

// windows api calls
//sys	FormatMessage(flags uint32, msgsrc uintptr, msgid uint32, langid uint32, buf []uint16, args *byte) (n uint32, err error) = FormatMessageW
