# Django Allauth Client

This project provides a fetch-based client for [Django Allauth](https://allauth.org/).

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
const allauthClient = new AllauthClient("app", "https://api.example.com");
``` 

### Session tokens for app clients

The client automatically handles session tokens for browser and app clients using cookies.

For `app` clients, you can provide an optional `storage` parameter to handle sessions. If not provided, the client will use a default cookie implementation which may not be suitable for all app environments.

The `storage` parameter should conform to the following interface:

```typescript
interface SessionStorage {
  getSessionToken(): Promise<string | null>;
  setSessionToken(value: string | null): Promise<void>;
}
```

Here's an example of how to create an AllauthClient instance with custom storage:

```typescript
const customStorage: SessionStorage = {
  async getSessionToken() {
    // Implement your custom logic to retrieve the session token
  },
  async setSessionToken(value: string | null) {
    // Implement your custom logic to store or remove the session token
  }
};

const allauthClient = new AllauthClient("app", "https://api.example.com", customStorage);
```

If you don't provide a custom storage, the client will use a default implementation that uses cookies:

```typescript
const allauthClient = new AllauthClient("app", "https://api.example.com");
```

More information on how headless Allauth handles session tokens can be found [here](https://docs.allauth.org/en/latest/headless/openapi-specification/#section/App-Usage/Session-Tokens).


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

#### List Provider Accounts

```typescript
const response = await allauthClient.listProviderAccounts(sessionToken);
```

#### Disconnect Provider Account

```typescript
const response = await allauthClient.disconnectProviderAccount(
  { provider: "google", account: "john@example.com" },
  sessionToken
);
```

### Email Address Management

#### List Email Addresses

```typescript
const response = await allauthClient.listEmailAddresses(sessionToken);
```

#### Add Email Address

```typescript
const response = await allauthClient.addEmailAddress(
  { email: "john@example.com" },
  sessionToken
);
```

#### Change Primary Email Address

```typescript
const response = await allauthClient.changePrimaryEmailAddress(
  { email: "john@example.com", primary: true },
  sessionToken
);
```

#### Remove Email Address

```typescript
const response = await allauthClient.removeEmailAddress(
  { email: "john@example.com" },
  sessionToken
);
```

### Multi-Factor Authentication (MFA)

#### List Authenticators

```typescript
const response = await allauthClient.listAuthenticators(sessionToken);
```

#### Get TOTP Authenticator

```typescript
const response = await allauthClient.getTOTPAuthenticator(
  sessionToken
);
```

#### Activate TOTP

```typescript
const response = await allauthClient.activateTOTP(
  { code: "123456" },
  sessionToken
);
```

#### Deactivate TOTP

```typescript
await allauthClient.deactivateTOTP(sessionToken);
```

#### List Recovery Codes

```typescript
const response = await allauthClient.listRecoveryCodes(sessionToken);
```

#### Regenerate Recovery Codes

```typescript
await allauthClient.regenerateRecoveryCodes(sessionToken);
```

### Session Management

#### List Sessions

```typescript
const response = await allauthClient.listSessions();
```

#### Delete Session

```typescript
const response = await allauthClient.deleteSession();
```

## Configuration

The `AllauthClient` constructor accepts the following parameters:

- `client`: The client type, either `'app'` or `'browser'`.
- `apiBaseUrl`: The base URL of the API.

Make sure to provide the correct values based on your API setup.
