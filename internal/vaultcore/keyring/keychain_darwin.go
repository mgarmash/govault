//go:build darwin && !ios

package keyring

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

const kCFStringEncodingUTF8 = 0x08000100

// Security.framework status codes.
const (
	errSecSuccess                = 0
	errSecItemNotFound           = -25300
	errSecInteractionNotAllowed  = -25308
	errSecAuthFailed             = -25293
	errSecNoSuchKeychain         = -25294
	errSecNotAvailable           = -25291
	errSecUserCanceled           = -128
	errSecInteractionRequired    = -25315
	errSecKeychainLockedOrAbsent = -25307
)

type keychainFuncs struct {
	CFRelease                 func(uintptr)
	CFDictionaryCreateMutable func(alloc uintptr, capacity int, keyCB, valueCB uintptr) uintptr
	CFDictionarySetValue      func(dict, key, value uintptr)
	CFDataCreate              func(alloc uintptr, bytes *byte, length int) uintptr
	CFDataGetBytePtr          func(data uintptr) *byte
	CFDataGetLength           func(data uintptr) int
	CFStringCreateWithCString func(alloc uintptr, s *byte, encoding uint32) uintptr
	SecItemAdd                func(attrs uintptr, result *uintptr) int32
	SecItemUpdate             func(query, attrs uintptr) int32
	SecItemCopyMatching       func(query uintptr, result *uintptr) int32
	SecItemDelete             func(query uintptr) int32
}

type keychainConsts struct {
	keyCallbacks, valueCallbacks, booleanTrue                        uintptr
	class, classGenericPassword, attrService, attrAccount, attrLabel uintptr
	valueData, returnData, matchLimit, matchLimitOne                 uintptr
	accessible, accessibleWhenUnlocked                               uintptr
}

var (
	kcOnce sync.Once
	kcErr  error
	kf     keychainFuncs
	kc     keychainConsts
)

func loadKeychain() error {
	kcOnce.Do(func() {
		cfLib, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			kcErr = err
			return
		}
		secLib, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			kcErr = err
			return
		}
		purego.RegisterLibFunc(&kf.CFRelease, cfLib, "CFRelease")
		purego.RegisterLibFunc(&kf.CFDictionaryCreateMutable, cfLib, "CFDictionaryCreateMutable")
		purego.RegisterLibFunc(&kf.CFDictionarySetValue, cfLib, "CFDictionarySetValue")
		purego.RegisterLibFunc(&kf.CFDataCreate, cfLib, "CFDataCreate")
		purego.RegisterLibFunc(&kf.CFDataGetBytePtr, cfLib, "CFDataGetBytePtr")
		purego.RegisterLibFunc(&kf.CFDataGetLength, cfLib, "CFDataGetLength")
		purego.RegisterLibFunc(&kf.CFStringCreateWithCString, cfLib, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&kf.SecItemAdd, secLib, "SecItemAdd")
		purego.RegisterLibFunc(&kf.SecItemUpdate, secLib, "SecItemUpdate")
		purego.RegisterLibFunc(&kf.SecItemCopyMatching, secLib, "SecItemCopyMatching")
		purego.RegisterLibFunc(&kf.SecItemDelete, secLib, "SecItemDelete")

		sym := func(lib uintptr, name string, deref bool) uintptr {
			addr, err := purego.Dlsym(lib, name)
			if err != nil {
				kcErr = err
				return 0
			}
			if !deref {
				return addr
			}
			return **(**uintptr)(unsafe.Pointer(&addr))
		}
		kc.keyCallbacks = sym(cfLib, "kCFTypeDictionaryKeyCallBacks", false)
		kc.valueCallbacks = sym(cfLib, "kCFTypeDictionaryValueCallBacks", false)
		kc.booleanTrue = sym(cfLib, "kCFBooleanTrue", true)
		for name, dst := range map[string]*uintptr{
			"kSecClass":                      &kc.class,
			"kSecClassGenericPassword":       &kc.classGenericPassword,
			"kSecAttrService":                &kc.attrService,
			"kSecAttrAccount":                &kc.attrAccount,
			"kSecAttrLabel":                  &kc.attrLabel,
			"kSecValueData":                  &kc.valueData,
			"kSecReturnData":                 &kc.returnData,
			"kSecMatchLimit":                 &kc.matchLimit,
			"kSecMatchLimitOne":              &kc.matchLimitOne,
			"kSecAttrAccessible":             &kc.accessible,
			"kSecAttrAccessibleWhenUnlocked": &kc.accessibleWhenUnlocked,
		} {
			*dst = sym(secLib, name, true)
		}
	})
	return kcErr
}

type cfScope struct{ owned []uintptr }

func (s *cfScope) keep(ref uintptr) uintptr {
	if ref != 0 {
		s.owned = append(s.owned, ref)
	}
	return ref
}

func (s *cfScope) release() {
	for _, r := range s.owned {
		kf.CFRelease(r)
	}
}

func (s *cfScope) str(v string) uintptr {
	b := append([]byte(v), 0)
	ref := kf.CFStringCreateWithCString(0, &b[0], kCFStringEncodingUTF8)
	runtime.KeepAlive(b)
	return s.keep(ref)
}

func (s *cfScope) data(v []byte) uintptr {
	var p *byte
	if len(v) > 0 {
		p = &v[0]
	}
	ref := kf.CFDataCreate(0, p, len(v))
	runtime.KeepAlive(v)
	return s.keep(ref)
}

func (s *cfScope) dict(pairs ...uintptr) uintptr {
	d := s.keep(kf.CFDictionaryCreateMutable(0, len(pairs)/2, kc.keyCallbacks, kc.valueCallbacks))
	for i := 0; i+1 < len(pairs); i += 2 {
		kf.CFDictionarySetValue(d, pairs[i], pairs[i+1])
	}
	return d
}

func (s *cfScope) query(service, account string, extra ...uintptr) uintptr {
	pairs := []uintptr{
		kc.class, kc.classGenericPassword,
		kc.attrService, s.str(service),
		kc.attrAccount, s.str(account),
	}
	return s.dict(append(pairs, extra...)...)
}

// keychain stores generic passwords in the user's login Keychain. The item
// ACL lets the binary that created it read it without a prompt; a
// differently signed binary gets a Keychain prompt, which a session with
// no GUI refuses with errSecInteractionNotAllowed.
type keychain struct{}

func system() (Store, error) {
	if err := loadKeychain(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return keychain{}, nil
}

func (keychain) Name() string { return "macos-keychain" }

func (keychain) Get(service, account string) ([]byte, error) {
	var s cfScope
	defer s.release()
	var result uintptr
	if err := status(kf.SecItemCopyMatching(s.query(service, account, kc.returnData, kc.booleanTrue, kc.matchLimit, kc.matchLimitOne), &result)); err != nil {
		return nil, err
	}
	s.keep(result)
	n := kf.CFDataGetLength(result)
	out := make([]byte, n)
	if n > 0 {
		copy(out, unsafe.Slice(kf.CFDataGetBytePtr(result), n))
	}
	return out, nil
}

func (keychain) Set(service, account string, secret []byte) error {
	var s cfScope
	defer s.release()
	err := status(kf.SecItemUpdate(s.query(service, account), s.dict(kc.valueData, s.data(secret))))
	if err != ErrNotFound {
		return err
	}
	attrs := s.query(service, account,
		kc.valueData, s.data(secret),
		kc.attrLabel, s.str(service),
		kc.accessible, kc.accessibleWhenUnlocked,
	)
	return status(kf.SecItemAdd(attrs, nil))
}

func (keychain) Delete(service, account string) error {
	var s cfScope
	defer s.release()
	if err := status(kf.SecItemDelete(s.query(service, account))); err != nil && err != ErrNotFound {
		return err
	}
	return nil
}

// KeychainError is a Security.framework status.
type KeychainError struct{ Status int32 }

func (e *KeychainError) Error() string {
	switch e.Status {
	case errSecInteractionNotAllowed, errSecInteractionRequired:
		return "keyring: the macOS Keychain needs user interaction, which this session does not allow (unlock it with `security unlock-keychain`)"
	case errSecKeychainLockedOrAbsent, errSecNoSuchKeychain, errSecNotAvailable:
		return "keyring: the macOS login Keychain is locked or unavailable"
	case errSecAuthFailed, errSecUserCanceled:
		return "keyring: access to the macOS Keychain was denied"
	}
	return fmt.Sprintf("keyring: macOS Keychain error %d", e.Status)
}

func status(code int32) error {
	switch code {
	case errSecSuccess:
		return nil
	case errSecItemNotFound:
		return ErrNotFound
	}
	return &KeychainError{Status: code}
}
