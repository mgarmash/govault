# Bitwarden new device verification

What Bitwarden's servers and clients do when a password login comes from a device the server does not know, and what GoVault implements. Sources: `bitwarden/server` [`f0bcb2c7`][server], `bitwarden/clients` [`ad5a8f31`][clients] (the revision gv follows), Vaultwarden [`c6e7da4b`][vw].

## Server

- **Where.** `BaseRequestValidator` runs `ValidateNewDeviceAsync` after the SSO and two-step checks, for every grant ([BaseRequestValidator.cs#L133-L177][order], [#L379-L391][validate]). `DeviceValidator.ValidateRequestDeviceAsync` makes the decision ([DeviceValidator.cs#L45-L122][validator]).
- **When it asks.** Only for the password grant (`GrantType.ResourceOwnerPassword`), only when the request needs neither two-step login nor SSO (`context is { TwoFactorRequired: false, SsoRequired: false }`), and only when `globalSettings.EnableNewDeviceVerification` is on ([#L92-L108][enforce]). That setting defaults to false and no shipped `appsettings`/self-host template sets it, so a self-hosted server asks only when its operator turns it on ([GlobalSettings.cs#L53][setting]).
- **When it skips.** A known device (`deviceIdentifier` already registered to the user) ([#L64-L75][known]); the user turned verification off (`User.VerifyDevices`, default true) ([#L141-L145][optout], [User.cs#L108][verifydevices]); an account less than 24 hours old ([#L147-L152][new24]); a one-time support exception in the cache ([#L154-L164][exception]); a user with no devices at all ([#L187-L192][nodevices]). API keys (`client_credentials`), SSO and auth requests never reach the check.
- **The challenge.** HTTP 400 with `error: "device_error"`, `error_description: "New device verification required"` and `ErrorModel.Message: "new device verification required"`; the server then emails a code bound to the user and the request's `deviceIdentifier` ([#L97-L106][enforce], [#L274-L311][errors]). The comment there says the message is what clients branch on.
- **The code.** Six digits, valid five minutes, bound to the device identifier and the security stamp, consumed on success ([NewDeviceVerificationOtpStore.cs][store], [OtpTokenProviderOptions.cs][otpopts], [OtpTokenProvider.cs#L60-L74][consume]).
- **The answer.** The same password grant again with the code in the form field `NewDeviceOtp` (read case-insensitively; clients send `newDeviceOtp`) ([#L166-L185][otp]). A wrong or expired code: HTTP 400, `device_error`, `error_description: "Invalid New Device OTP"`, `ErrorModel.Message: "invalid new device otp"`. An empty field counts as absent ([#L264-L267][hasotp]).
- **Resend.** `POST /api/accounts/resend-new-device-otp`, anonymous, JSON `{"email", "masterPasswordHash"}`; the code is bound to the `Device-Identifier` header. It answers success whatever the password, to avoid account enumeration ([AccountsController.cs#L862-L910][resend]).

## Clients

- **Detection.** `ApiService.postIdentityToken` maps a 400 whose `ErrorModel.Message` is `"new device verification required"` to `IdentityDeviceVerificationResponse`, after the two-step check ([api.service.ts#L118-L123, #L192-L203][detect]). Unauthenticated requests carry `Device-Identifier` ([#L1597-L1602][devhdr]).
- **Retry.** `PasswordLoginStrategy.logInNewDeviceVerification` repeats the cached token request with `newDeviceOtp` ([password-login.strategy.ts#L271-L279][retry], [password-token.request.ts#L25-L27][field]).
- **Desktop/web.** `NewDeviceVerificationComponent`: title "Verify your Identity", "We don't recognize this device. Enter the code sent to your email to verify your identity.", a Verification code field, Resend code, Continue logging in, Back. A server error containing "Invalid New Device OTP" shows "Invalid verification code" ([component.ts#L108-L192][component], [component.html][html]).
- **CLI.** `bw login` prompts "New device verification required. Enter OTP sent to login email:" and has no option for the code; without interaction (`--nointeraction`/`BW_NOINTERACTION`) it fails with "Code is required." ([login.command.ts#L336-L355][cli]). A wrong code reaches the generic handler, which prints `ErrorModel.Message`, "invalid new device otp". The recorded fixture `internal/cli/testdata/bw/login-new-device.json` confirms the non-interactive output of bw 2026.11.0.

## Vaultwarden

No new device verification: it only emails a "new device logged in" notice after a successful login ([identity.rs#L593][vw593], [#L745][vw745]). Nothing in GoVault changes against it.

## GoVault

- `api`: `*NewDeviceVerificationRequiredError` (matches `ErrNewDeviceVerificationRequired`), a wrong code as an `*APIError` that also matches `ErrInvalidNewDeviceOTP`, `PasswordLoginOptions.NewDeviceOTP`, `Client.ResendNewDeviceOTP`.
- Desktop: the sign-in card's new device step (Resend Code, Back to Sign In); `state.Service.ResendNewDeviceOTP` goes only to the trusted server for Sign In Again.
- `gv login`: bw's prompt, "Code is required." without interaction, bw's message for a wrong code.

[server]: https://github.com/bitwarden/server/tree/f0bcb2c70914f1e11a9b335e5c0bae59da599d48
[clients]: https://github.com/bitwarden/clients/tree/ad5a8f316667f875737c01ec77b6632ab4884430
[vw]: https://github.com/dani-garcia/vaultwarden/tree/c6e7da4b5c36495568923694031d5406deb3c736
[order]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/BaseRequestValidator.cs#L133-L177
[validate]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/BaseRequestValidator.cs#L379-L391
[validator]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L45-L122
[enforce]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L92-L108
[known]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L64-L75
[optout]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L141-L145
[new24]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L147-L152
[exception]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L154-L164
[otp]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L166-L185
[nodevices]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L187-L192
[hasotp]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L264-L267
[errors]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs#L274-L311
[setting]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Core/Settings/GlobalSettings.cs#L53
[verifydevices]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Core/Entities/User.cs#L108
[store]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Core/Auth/Services/Implementations/NewDeviceVerificationOtpStore.cs
[otpopts]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Core/Auth/Identity/TokenProviders/OtpTokenProvider/OtpTokenProviderOptions.cs
[consume]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Core/Auth/Identity/TokenProviders/OtpTokenProvider/OtpTokenProvider.cs#L60-L74
[resend]: https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Api/Auth/Controllers/AccountsController.cs#L862-L910
[detect]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/libs/common/src/services/api.service.ts#L118-L203
[devhdr]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/libs/common/src/services/api.service.ts#L1597-L1602
[retry]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/libs/auth/src/common/login-strategies/password-login.strategy.ts#L271-L279
[field]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/libs/common/src/auth/models/request/identity-token/password-token.request.ts#L25-L27
[component]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/libs/auth/src/angular/new-device-verification/new-device-verification.component.ts#L108-L192
[html]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/libs/auth/src/angular/new-device-verification/new-device-verification.component.html
[cli]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/auth/commands/login.command.ts#L336-L355
[vw593]: https://github.com/dani-garcia/vaultwarden/blob/c6e7da4b5c36495568923694031d5406deb3c736/src/api/identity.rs#L593
[vw745]: https://github.com/dani-garcia/vaultwarden/blob/c6e7da4b5c36495568923694031d5406deb3c736/src/api/identity.rs#L745
