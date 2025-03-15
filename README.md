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

Create an instance of the `AllauthClient` by providing the base URL of the API:

```typescript
const allauthClient = new AllauthClient("https://api.example.com");
```

By default, the client type is set to "browser". If you want to use the "app" client type:

```typescript
const allauthClient = new AllauthClient(
  "https://api.example.com",
  "/csrf-token/",
  "app"
);
```

### CSRF Token Support

For browser clients, you can provide a `csrfTokenEndpoint` parameter to specify an endpoint for fetching CSRF tokens. This is useful when your Django backend requires CSRF protection for non-GET requests:

```typescript
const allauthClient = new AllauthClient(
  "https://api.example.com", // API base URL
  "/csrf-token/" // CSRF token endpoint
);
```

If provided, the client will automatically fetch a CSRF token before making non-GET requests and include it in the `X-CSRFToken` header.

### Session tokens for app clients

The client automatically handles session tokens for browser and app clients using cookies.

For `app` clients, you can provide an optional `storage` parameter to handle sessions. If not provided, the client will use a default cookie implementation which may not be suitable for all app environments.

The `storage` parameter should conform to the following interface:

```typescript
interface SessionStorage {
  getSessionToken(): Promise<string | null>;
  setSessionToken(value: string | null): Promise<void>;
  getCSRFToken(): Promise<string | null>;
  setCSRFToken(value: string | null): Promise<void>;
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
  },
  async getCSRFToken() {
    // Implement your custom logic to retrieve the CSRF token
  },
  async setCSRFToken(value: string | null) {
    // Implement your custom logic to store or remove the CSRF token
  },
};

const allauthClient = new AllauthClient(
  "https://api.example.com", // API base URL
  undefined, // No CSRF token endpoint
  "app", // Client type
  customStorage // Custom storage implementation
);
```

If you don't provide a custom storage, the client will use a default implementation that uses cookies:

```typescript
const allauthClient = new AllauthClient(
  "https://api.example.com",
  "/csrf-token/"
);
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
const response = await allauthClient.getTOTPAuthenticator(sessionToken);
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

- `apiBaseUrl`: The base URL of the API.
- `csrfTokenEndpoint`: (Optional) The endpoint to fetch CSRF tokens from. If provided, the client will automatically fetch a CSRF token before making non-GET requests.
- `clientType`: (Optional) The client type, either `'app'` or `'browser'`. Defaults to `'browser'`.
- `storage`: (Optional) A custom storage implementation for managing session tokens and CSRF tokens. If not provided, a default cookie-based implementation will be used.

Make sure to provide the correct values based on your API setup.

### CSRF Token Handling

When using the `csrfTokenEndpoint` parameter:

1. The client will check if a CSRF token is already available in storage before making a non-GET request.
2. If no token is found, it will make a GET request to the specified endpoint to fetch a new token.
3. The token will be stored using the provided storage implementation.
4. The token will be included in the `X-CSRFToken` header for all subsequent non-GET requests.

The endpoint should return a JSON response with a `token` field containing the CSRF token:

```json
{
  "token": "your-csrf-token-value"
}
```

If the token is set as a cookie by the server, the client will attempt to retrieve it from the cookie storage.
