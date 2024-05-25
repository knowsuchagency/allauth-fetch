# Django Allauth Client

This project provides a fetch-based client library and higher-level react context for the excellent [Django Allauth](https://allauth.org/) library.

The `AllauthClient` module provides a client-side library for interacting with the authentication and account management endpoints of the [django-allauth openapi spec](https://docs.allauth.org/en/latest/headless/openapi-specification/). It supports both browser-based and app-based authentication flows.

## Installation

Install the `AllauthClient` module using your preferred package manager. For example, using npm:

```bash
npx jsr add @knowsuchagency/allauth-fetch
```

## Usage

### Importing the AllauthClient

```typescript
import { AllauthClient } from "@knowsuchagency/allauth-fetch";
```

### Creating an AllauthClient Instance

Create an instance of the `AllauthClient` by providing the client type (`'app'` or `'browser'`) and the base URL of the API:

```typescript
const allauthClient = new AllauthClient("browser", "https://api.example.com");
```

### Authentication Methods

#### Login

```typescript
const response = await allauthClient.login({
  username: "john",
  password: "secret",
});
```

#### Signup

```typescript
const response = await allauthClient.signup({
  email: "john@example.com",
  password: "secret",
});
```

#### Logout

```typescript
await allauthClient.logout(sessionToken);
```

#### Get Authentication Status

```typescript
const response = await allauthClient.getAuthenticationStatus(sessionToken);
```

### Email Verification

#### Get Email Verification Info

```typescript
const response = await allauthClient.getEmailVerificationInfo(key);
```

#### Verify Email

```typescript
const response = await allauthClient.verifyEmail({ key }, sessionToken);
```

### Password Management

#### Request Password Reset

```typescript
await allauthClient.requestPassword({ email: "john@example.com" });
```

#### Get Password Reset Info

```typescript
const response = await allauthClient.getPasswordResetInfo(key);
```

#### Reset Password

```typescript
const response = await allauthClient.resetPassword({
  key,
  password: "newPassword",
});
```

#### Change Password

```typescript
await allauthClient.changePassword(
  { current_password: "oldPassword", new_password: "newPassword" },
  sessionToken
);
```

### Social Account Management

#### Get Provider Accounts

```typescript
const providerAccounts = await allauthClient.getProviderAccounts(sessionToken);
```

#### Disconnect Provider Account

```typescript
const providerAccounts = await allauthClient.disconnectProviderAccount(
  { provider: "google", account: "john@example.com" },
  sessionToken
);
```

### Email Address Management

#### Get Email Addresses

```typescript
const emailAddresses = await allauthClient.getEmailAddresses(sessionToken);
```

#### Add Email Address

```typescript
const emailAddresses = await allauthClient.addEmailAddress(
  { email: "john@example.com" },
  sessionToken
);
```

#### Change Primary Email Address

```typescript
const emailAddresses = await allauthClient.changePrimaryEmailAddress(
  { email: "john@example.com", primary: true },
  sessionToken
);
```

#### Remove Email Address

```typescript
const emailAddresses = await allauthClient.removeEmailAddress(
  { email: "john@example.com" },
  sessionToken
);
```

### Multi-Factor Authentication (MFA)

#### Get Authenticators

```typescript
const authenticators = await allauthClient.getAuthenticators(sessionToken);
```

#### Get TOTP Authenticator

```typescript
const totpAuthenticator = await allauthClient.getTOTPAuthenticator(
  sessionToken
);
```

#### Activate TOTP

```typescript
const totpAuthenticator = await allauthClient.activateTOTP(
  { code: "123456" },
  sessionToken
);
```

#### Deactivate TOTP

```typescript
await allauthClient.deactivateTOTP(sessionToken);
```

#### Get Recovery Codes

```typescript
const recoveryCodes = await allauthClient.getRecoveryCodes(sessionToken);
```

#### Regenerate Recovery Codes

```typescript
await allauthClient.regenerateRecoveryCodes(sessionToken);
```

### Session Management

#### Get Sessions

```typescript
const sessions = await allauthClient.getSessions();
```

#### Delete Session

```typescript
const sessions = await allauthClient.deleteSession();
```

## Configuration

The `AllauthClient` constructor accepts the following parameters:

- `client`: The client type, either `'app'` or `'browser'`.
- `apiBaseUrl`: The base URL of the API.

Make sure to provide the correct values based on your API setup.
