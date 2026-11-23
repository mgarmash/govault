package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// New device verification: Bitwarden's cloud asks for a code sent to the
// account's email when a password login comes from a device it does not
// know, for accounts without two-step login. The identity server answers
// the password grant with HTTP 400, error "device_error" and
// ErrorModel.Message "new device verification required", and emails a
// six-digit code bound to the device identifier, valid five minutes. The
// client repeats the grant with the code in newDeviceOtp; a wrong code is
// refused with ErrorModel.Message "invalid new device otp". API keys, SSO,
// two-step accounts and known devices skip the check, and a self-hosted
// server only asks when EnableNewDeviceVerification is set. Vaultwarden has
// no such check.
//
// bitwarden/server f0bcb2c7: src/Identity/IdentityServer/RequestValidators/
// DeviceValidator.cs (ValidateRequestDeviceAsync, BuildDeviceErrorResult),
// src/Api/Auth/Controllers/AccountsController.cs (ResendNewDeviceOtpAsync).
// bitwarden/clients ad5a8f31: libs/common/src/services/api.service.ts
// (NEW_DEVICE_VERIFICATION_REQUIRED_MESSAGE), password-token.request.ts.

var (
	// ErrNewDeviceVerificationRequired matches a
	// *NewDeviceVerificationRequiredError.
	ErrNewDeviceVerificationRequired = errors.New("api: new device verification required")
	// ErrInvalidNewDeviceOTP matches the *APIError a server answers a
	// wrong or expired new device verification code with.
	ErrInvalidNewDeviceOTP = errors.New("api: invalid new device verification code")
)

const (
	newDeviceRequiredMessage   = "new device verification required"
	newDeviceInvalidOTPMessage = "invalid new device otp"
)

// NewDeviceVerificationRequiredError means the server emailed a code to
// verify this device; repeat the login with it in
// PasswordLoginOptions.NewDeviceOTP.
type NewDeviceVerificationRequiredError struct {
	Message string
}

func (e *NewDeviceVerificationRequiredError) Error() string {
	return ErrNewDeviceVerificationRequired.Error()
}

func (e *NewDeviceVerificationRequiredError) Unwrap() error { return ErrNewDeviceVerificationRequired }

// invalidNewDeviceOTPError is an *APIError, to errors.As, that also
// matches ErrInvalidNewDeviceOTP; its Message is the server's, as bw
// prints it.
type invalidNewDeviceOTPError struct{ APIError }

func (e *invalidNewDeviceOTPError) Error() string { return e.APIError.Error() }

func (e *invalidNewDeviceOTPError) Is(target error) bool { return target == ErrInvalidNewDeviceOTP }

func (e *invalidNewDeviceOTPError) As(target any) bool {
	if p, ok := target.(**APIError); ok {
		*p = &e.APIError
		return true
	}
	return false
}

// newDeviceError recognizes the identity server's device_error answers by
// ErrorModel.Message, the field Bitwarden's clients branch on.
func newDeviceError(status int, body []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return nil
	}
	var model struct {
		Message string `json:"message"`
	}
	for k, v := range fields {
		if strings.EqualFold(k, "errorModel") {
			_ = json.Unmarshal(v, &model)
		}
	}
	switch strings.ToLower(strings.TrimSpace(model.Message)) {
	case newDeviceRequiredMessage:
		return &NewDeviceVerificationRequiredError{Message: model.Message}
	case newDeviceInvalidOTPMessage:
		var parsed struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &parsed)
		return &invalidNewDeviceOTPError{APIError{StatusCode: status, Message: model.Message, Code: parsed.Error, Body: string(body)}}
	}
	return nil
}

// ResendNewDeviceOTP asks the server to email a new device verification
// code again (POST /api/accounts/resend-new-device-otp). The code is bound
// to the Device-Identifier sent with it, so the login that follows must
// use the same client. The server answers success even for a wrong
// password, so this cannot tell whether an email was sent.
func (c *Client) ResendNewDeviceOTP(ctx context.Context, email, masterPasswordHash string) error {
	body, err := json.Marshal(struct {
		Email              string `json:"email"`
		MasterPasswordHash string `json:"masterPasswordHash"`
	}{
		Email:              crypto.NormalizeEmail(email),
		MasterPasswordHash: masterPasswordHash,
	})
	if err != nil {
		return err
	}
	headers := map[string]string{"Device-Identifier": c.deviceID}
	_, err = c.do(ctx, http.MethodPost, "/api/accounts/resend-new-device-otp", "application/json", "", headers, body)
	return err
}
