type Client = "app" | "browser";

export interface ConfigurationResponse {
  status: number;
  data: {
    account: {
      authentication_method: "email" | "username" | "username_email";
    };
    socialaccount: {
      providers: Provider[];
    };
    mfa: {
      supported_types: AuthenticatorType[];
    };
    usersessions: {
      track_activity: boolean;
    };
  };
}

export interface Provider {
  id: string;
  name: string;
  client_id?: string;
  flows: ("provider_redirect" | "provider_token")[];
}

type AuthenticatorType = "recovery_codes" | "totp";

interface AuthenticationResponse {
  status: number;
  data: {
    flows: Flow[];
  };
  meta: {
    is_authenticated: boolean;
    session_token?: string;
    access_token?: string;
  };
}

export interface Flow {
  id:
    | "verify_email"
    | "login"
    | "signup"
    | "provider_redirect"
    | "provider_signup"
    | "provider_token"
    | "mfa_authenticate"
    | "reauthenticate"
    | "mfa_reauthenticate";
  provider?: Provider;
  is_pending?: boolean;
}

export interface AuthenticatedResponse {
  status: number;
  data: {
    user: User;
    methods: AuthenticationMethod[];
  };
  meta: {
    is_authenticated: true;
    session_token?: string;
    access_token?: string;
  };
}

export interface User {
  id: number | string;
  display: string;
  has_usable_password: boolean;
  email: string;
  username?: string;
}

type AuthenticationMethod =
  | {
      method: "password";
      at: number;
      email?: string;
      username?: string;
    }
  | {
      method: "password";
      at: number;
      reauthenticated: true;
    }
  | {
      method: "socialaccount";
      at: number;
      provider: string;
      uid: string;
    }
  | {
      method: "mfa";
      at: number;
      type: AuthenticatorType;
      reauthenticated?: boolean;
    };

export interface ErrorResponse {
  status: number;
  errors: {
    code: string;
    param?: string;
    message: string;
  }[];
}

export interface NotAuthenticatedResponse {
  status: number;
  data: {
    flows: Flow[];
  };
  meta: {
    is_authenticated: false;
    session_token?: string;
    access_token?: string;
  };
}

export interface ForbiddenResponse {
  status: 403;
}

export interface NoAuthenticatedSessionResponse {
  status: 401;
  data: Flow[];
  meta: {
    session_token?: string;
    access_token?: string;
    is_authenticated: false;
  };
}

export interface SessionInvalidOrNoLongerExists {
  status: 410;
}

export interface TOTPAuthenticatorResponse {
  status: number;
  data: TOTPAuthenticator;
}

export interface NoTOTPAuthenticatorResponse {
  status: 404;
  data: {
    meta: {
      secret: string;
    };
  };
}

export interface EmailVerificationInfoResponse {
  status: number;
  data: {
    email: string;
    user: User;
  };
  meta: {
    is_authenticating: boolean;
  };
}

export interface PasswordResetInfoResponse {
  status: number;
  data: {
    user: User;
  };
}

export interface EmailAddress {
  email: string;
  primary: boolean;
  verified: boolean;
}

export interface EmailAddressesResponse {
  status: number;
  data: EmailAddress[];
}

export interface ProviderAccount {
  uid: string;
  display: string;
  provider: Provider;
}

export interface ProviderAccountsResponse {
  status: number;
  data: ProviderAccount[];
}

export interface TOTPAuthenticator {
  type: "totp";
  last_used_at: number | null;
  created_at: number;
}

export interface RecoveryCodesAuthenticator {
  type: "recovery_codes";
  last_used_at: number | null;
  created_at: number;
  total_code_count: number;
  unused_code_count: number;
}

export interface AuthenticatorsResponse {
  status: number;
  data: (TOTPAuthenticator | RecoveryCodesAuthenticator)[];
}

export interface SensitiveRecoveryCodesAuthenticator
  extends RecoveryCodesAuthenticator {
  unused_codes: string[];
}

export interface SensitiveRecoveryCodesAuthenticatorResponse {
  status: number;
  data: SensitiveRecoveryCodesAuthenticator;
}

export interface Session {
  user_agent: string;
  ip: string;
  created_at: number;
  is_current: boolean;
  id: number;
  last_seen_at?: number;
}

export interface SessionsResponse {
  status: number;
  data: Session[];
}

function getCookie(name): string | undefined {
  if (document.cookie && document.cookie !== "") {
    const cookies = document.cookie.split(";");
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      // Does this cookie string begin with the name we want?
      if (cookie.substring(0, name.length + 1) === name + "=") {
        return decodeURIComponent(cookie.substring(name.length + 1));
      }
    }
  }
}

export function getCSRFToken(): string | undefined {
  return getCookie("csrftoken");
}

export function getSessionId(): string | undefined {
  return getCookie("sessionid");
}

interface SessionStorage {
  getSessionToken(): Promise<string | null>;
  setSessionToken(value: string | null): Promise<void>;
}

class CookieSessionStorage implements SessionStorage {
  async getSessionToken(): Promise<string | null> {
    return getCookie("sessiontoken") || null;
  }

  async setSessionToken(value: string | null): Promise<void> {
    if (value) {
      document.cookie = `sessiontoken=${value}; path=/; secure; samesite=lax`;
    } else {
      document.cookie = "sessiontoken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    }
  }
}

/**
 * `AllauthClient` is a class that provides methods to interact with the Allauth API.
 * It supports both browser and app clients.
 * 
 * For app clients, it uses an optional `AsyncStorage` instance to manage session tokens.
 * Session tokens are used to maintain the session state in the absence of cookies.
 * 
 * The session token is sent in the `X-Session-Token` header of each request after it's obtained.
 * 
 * Session tokens can be found in the `meta.session_token` field of authentication related responses.
 * When a new session token is received, it should overwrite the previous one and be used in all subsequent requests.
 * 
 * If a response with status code 410 (Gone) is received, it indicates that the session is no longer valid.
 * In this case, the session token should be removed and a new session should be started.
 * 
 * @param {Client} client - The client type, either "browser" or "app".
 * @param {string} apiBaseUrl - The base URL of the Allauth API.
 * @param {AsyncStorage | null} storage - An optional instance of AsyncStorage for managing session tokens in app clients.
 */
export class AllauthClient {
  private apiBaseUrl: string;
  private storage: SessionStorage;

  constructor(
    private client: Client,
    apiBaseUrl: string,
    storage?: SessionStorage
  ) {
    this.apiBaseUrl = `${apiBaseUrl}/_allauth/${client}/v1`;
    this.storage = storage || new CookieSessionStorage();
  }

  private async fetchData<T>(
    url: string,
    options?: {
      method?: string;
      headers?: Record<string, string>;
      body?: any;
    }
  ): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...options?.headers,
    };

    if (this.client === "browser") {
      const csrfToken = getCSRFToken();
      if (csrfToken) {
        console.log("csrf token detected. adding to headers");
        headers["X-CSRFToken"] = csrfToken;
      } else {
        console.log("no csrf token detected");
      }
    }

    const sessionToken = await this.storage.getSessionToken();
    if (sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    console.log("headers", headers);

    const response = await fetch(`${this.apiBaseUrl}${url}`, {
      ...options,
      headers,
      credentials: 'include',
      mode: 'cors',
      body: options?.body ? JSON.stringify(options.body) : undefined,
    });

    if (!response.ok) {
      if (response.status === 410) {
        await this.storage.setSessionToken(null);
      }

      const errorData: ErrorResponse = await response.json();
      if (
        errorData.errors &&
        Array.isArray(errorData.errors) &&
        errorData.errors.length > 0
      ) {
        throw new Error(errorData.errors[0]?.message || "Something went wrong");
      } else {
        throw new Error("Something went wrong");
      }
    }

    const responseJson = await response.json() as any;

    if (responseJson.meta?.session_token) {
      await this.storage.setSessionToken(responseJson.meta.session_token);
    }

    return responseJson;
  }

  async getConfiguration(): Promise<ConfigurationResponse> {
    return this.fetchData<ConfigurationResponse>("/config");
  }

  async login(
    data: {
      username?: string;
      email?: string;
      password: string;
    }
  ): Promise<AuthenticatedResponse | ErrorResponse | NotAuthenticatedResponse> {
    return this.fetchData<
      AuthenticatedResponse | ErrorResponse | NotAuthenticatedResponse
    >("/auth/login", {
      method: "POST",
      body: data,
    });
  }

  async signup(
    data: {
      email?: string;
      username?: string;
      password: string;
    }
  ): Promise<
    | AuthenticatedResponse
    | ErrorResponse
    | NotAuthenticatedResponse
    | ForbiddenResponse
  > {
    return this.fetchData<
      | AuthenticatedResponse
      | ErrorResponse
      | NotAuthenticatedResponse
      | ForbiddenResponse
    >("/auth/signup", {
      method: "POST",
      body: data,
    });
  }

  async getEmailVerificationInfo(
    key: string
  ): Promise<EmailVerificationInfoResponse | ErrorResponse> {
    const headers = { "X-Email-Verification-Key": key };
    return this.fetchData<EmailVerificationInfoResponse | ErrorResponse>(
      "/auth/email/verify",
      {
        headers,
      }
    );
  }

  async verifyEmail(
    data: { key: string }
  ): Promise<
    AuthenticatedResponse | ErrorResponse | NoAuthenticatedSessionResponse
  > {
    return this.fetchData<
      AuthenticatedResponse | ErrorResponse | NoAuthenticatedSessionResponse
    >("/auth/email/verify", {
      method: "POST",
      body: data,
    });
  }

  async reauthenticate(
    data: { password: string }
  ): Promise<AuthenticatedResponse | ErrorResponse> {
    return this.fetchData<AuthenticatedResponse | ErrorResponse>(
      "/auth/reauthenticate",
      {
        method: "POST",
        body: data,
      }
    );
  }

  async requestPassword(
    data: {
      email: string;
    }
  ): Promise<{ status: 200 } | ErrorResponse> {
    return this.fetchData<{ status: 200 } | ErrorResponse>(
      "/auth/password/request",
      {
        method: "POST",
        body: data,
      }
    );
  }

  async getPasswordResetInfo(
    key: string
  ): Promise<PasswordResetInfoResponse | ErrorResponse> {
    const headers: Record<string, string> = {
      "X-Password-Reset-Key": key,
    };
    return this.fetchData<PasswordResetInfoResponse | ErrorResponse>(
      "/auth/password/reset",
      { headers }
    );
  }

  async resetPassword(data: {
    key: string;
    password: string;
    
  }): Promise<{ status: 200 } | ErrorResponse> {
    return this.fetchData<{ status: 200 } | ErrorResponse>(
      "/auth/password/reset",
      {
        method: "POST",
        body: data,
      }
    );
  }

  async providerRedirect(
    provider: string,
    callbackUrl: string,
    process: "login" | "connect"
  ): Promise<string> {
    const formData = new URLSearchParams();
    formData.append("provider", provider);
    formData.append("callback_url", callbackUrl);
    formData.append("process", process);
    const response = await fetch(
      `${this.apiBaseUrl}/_allauth/${this.client}/v1/auth/provider/redirect`,
      {
        method: "POST",
        body: formData,
      }
    );
    if (!response.ok) {
      const errorData: ErrorResponse = await response.json();
      throw new Error(errorData.errors[0]?.message || "Something went wrong");
    }
    const location = response.headers["location"];
    if (!location) {
      throw new Error("Location header is missing");
    }
    return location;
  }

  async providerToken(
    data: {
      provider: string;
      process: "login" | "connect";
      token: { client_id: string; id_token?: string; access_token?: string };
    }
  ): Promise<
    | AuthenticatedResponse
    | NotAuthenticatedResponse
    | ErrorResponse
    | ForbiddenResponse
  > {
    return this.fetchData<
      | AuthenticatedResponse
      | NotAuthenticatedResponse
      | ErrorResponse
      | ForbiddenResponse
    >("/auth/provider/token", {
      method: "POST",
      body: data,
    });
  }

  async providerSignup(
    data: {
      email: string;
    }
  ): Promise<
    | AuthenticatedResponse
    | NotAuthenticatedResponse
    | ErrorResponse
    | ForbiddenResponse
    | { status: 409 }
  > {
    return this.fetchData<
      | AuthenticatedResponse
      | NotAuthenticatedResponse
      | ErrorResponse
      | ForbiddenResponse
      | { status: 409 }
    >("/auth/provider/signup", {
      method: "POST",
      body: data,
    });
  }

  async mfaAuthenticate(
    data: { code: string }
  ): Promise<AuthenticatedResponse | ErrorResponse | NotAuthenticatedResponse> {
    return this.fetchData<
      AuthenticatedResponse | ErrorResponse | NotAuthenticatedResponse
    >("/auth/2fa/authenticate", {
      method: "POST",
      body: data,
    });
  }

  async mfaReauthenticate(
  ): Promise<AuthenticatedResponse | ErrorResponse> {
    return this.fetchData<AuthenticatedResponse | ErrorResponse>(
      "/auth/2fa/reauthenticate",
      {
        method: "POST",
      }
    );
  }

  async requestLoginCode(
    data: { email: string }
  ): Promise<ErrorResponse | NotAuthenticatedResponse> {
    return this.fetchData<ErrorResponse | NotAuthenticatedResponse>(
      "/auth/code/request",
      {
        method: "POST",
        body: data,
      }
    );
  }

  async confirmLoginCode(data: {
    code: string;
  }): Promise<
    AuthenticatedResponse | NotAuthenticatedResponse | ErrorResponse
  > {
    return this.fetchData<
      AuthenticatedResponse | NotAuthenticatedResponse | ErrorResponse
    >("/auth/code/confirm", {
      method: "POST",
      body: data,
    });
  }

  async listProviderAccounts(
  ): Promise<ProviderAccountsResponse> {
    return this.fetchData<ProviderAccountsResponse>("/account/providers");
  }

  async disconnectProviderAccount(
    data: { provider: string; account: string }
  ): Promise<ProviderAccountsResponse | ErrorResponse> {
    return this.fetchData<ProviderAccountsResponse | ErrorResponse>(
      "/account/providers",
      {
        method: "DELETE",
        body: data,
      }
    );
  }

  async listEmailAddresses(
  ): Promise<EmailAddressesResponse | NotAuthenticatedResponse> {
    return this.fetchData<EmailAddressesResponse | NotAuthenticatedResponse>(
      "/account/email"
    );
  }

  async addEmailAddress(
    data: { email: string }
  ): Promise<
    EmailAddressesResponse | ErrorResponse | NotAuthenticatedResponse
  > {
    return this.fetchData<
      EmailAddressesResponse | ErrorResponse | NotAuthenticatedResponse
    >("/account/email", {
      method: "POST",
      body: data,
    });
  }

  async requestEmailVerification(
    data: { email: string }
  ): Promise<{ status: 200 | 400 | 403 }> {
    return this.fetchData<{ status: 200 | 400 | 403 }>("/account/email", {
      method: "PUT",
      body: data,
    });
  }

  async changePrimaryEmailAddress(
    data: { email: string; primary: true }
  ): Promise<EmailAddressesResponse | ErrorResponse> {
    return this.fetchData<EmailAddressesResponse | ErrorResponse>(
      "/account/email",
      {
        method: "PATCH",
        body: data,
      }
    );
  }

  async removeEmailAddress(
    data: { email: string }
  ): Promise<EmailAddressesResponse | ErrorResponse> {
    return this.fetchData<EmailAddressesResponse | ErrorResponse>(
      "/account/email",
      {
        method: "DELETE",
        body: data,
      }
    );
  }

  async listAuthenticators(
  ): Promise<AuthenticatorsResponse> {
    return this.fetchData<AuthenticatorsResponse>("/account/authenticators");
  }

  async getTOTPAuthenticator(
  ): Promise<TOTPAuthenticatorResponse | NoTOTPAuthenticatorResponse> {
    return this.fetchData<
      TOTPAuthenticatorResponse | NoTOTPAuthenticatorResponse
    >("/account/authenticators/totp");
  }

  async activateTOTP(
    data: { code: string }
  ): Promise<TOTPAuthenticatorResponse | ErrorResponse> {
    return this.fetchData<TOTPAuthenticatorResponse | ErrorResponse>(
      "/account/authenticators/totp",
      {
        method: "POST",
        body: data,
      }
    );
  }

  async deactivateTOTP(): Promise<{ status: 200 | 401 }> {
    return this.fetchData<{ status: 200 | 401 }>(
      "/account/authenticators/totp",
      {
        method: "DELETE",
      }
    );
  }

  async listRecoveryCodes(
  ): Promise<
    SensitiveRecoveryCodesAuthenticatorResponse | { status: 401 | 404 }
  > {
    return this.fetchData<
      SensitiveRecoveryCodesAuthenticatorResponse | { status: 401 | 404 }
    >("/account/authenticators/recovery_codes");
  }

  async regenerateRecoveryCodes(
  ): Promise<ErrorResponse | { status: 401 }> {
    return this.fetchData<ErrorResponse | { status: 401 }>(
      "/account/authenticators/recovery_codes",
      {
        method: "POST",
      }
    );
  }

  async getAuthenticationStatus(
  ): Promise<
    | AuthenticatedResponse
    | NotAuthenticatedResponse
    | SessionInvalidOrNoLongerExists
  > {
    return this.fetchData<
      | AuthenticatedResponse
      | NotAuthenticatedResponse
      | SessionInvalidOrNoLongerExists
    >("/auth/session");
  }

  async logout(): Promise<NoAuthenticatedSessionResponse> {
    if (this.client === "app") {
      const sessionToken = await this.storage.getSessionToken();
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
    }

    const response = await this.fetchData<NoAuthenticatedSessionResponse>("/auth/session", {
      method: "DELETE",
    });

    if (this.client === "app") {
      await this.storage.setSessionToken(null);
    }

    return response;
  }

  async changePassword(
    data: { current_password?: string; new_password: string }
  ): Promise<NotAuthenticatedResponse | ErrorResponse> {
    return this.fetchData<NotAuthenticatedResponse | ErrorResponse>(
      "/account/password/change",
      {
        method: "POST",
        body: data,
      }
    );
  }

  async listSessions(): Promise<SessionsResponse> {
    return this.fetchData<SessionsResponse>("/sessions");
  }

  async deleteSession(): Promise<SessionsResponse> {
    return this.fetchData<SessionsResponse>("/sessions", { method: "DELETE" });
  }
}
