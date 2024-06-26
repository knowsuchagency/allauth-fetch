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

interface AsyncStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string | null): Promise<void>;
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

  constructor(private client: Client, apiBaseUrl: string, private storage?: AsyncStorage | null) {
    this.apiBaseUrl = `${apiBaseUrl}/_allauth/${client}/v1`;
  }

  private async fetchData<T>(
    url: string,
    options?: {
      method?: string;
      headers?: Record<string, string>;
      body?: any;
    }
  ): Promise<T> {
    if (this.client === "browser") {
      const headers = {};
      const csrfToken = getCSRFToken();
      if (csrfToken) {
        headers["X-CSRFToken"] = csrfToken;
      }
      const sessionId = getSessionId();
      if (sessionId) {
        headers["X-Session-Token"] = sessionId;
      }
      options = {
        ...options,
        headers: headers,
      };
    }

    if (this.client === "app" && this.storage) {
      const sessionToken = await this.storage.get("sessionToken");
      if (sessionToken) {
        options = {
          ...options,
          headers: {
            ...options?.headers,
            "X-Session-Token": sessionToken,
          },
        };
      }
    }

    const response = await fetch(`${this.apiBaseUrl}${url}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
      body: options?.body ? JSON.stringify(options.body) : undefined,
    });

    if (!response.ok) {
      if (response.status === 410 && this.client === "app" && this.storage) {
        await this.storage.set("sessionToken", null);
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

    if (this.client === "app" && this.storage) {
      if (responseJson.meta?.session_token) {
        await this.storage.set("sessionToken", responseJson.meta.session_token);
      }
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
    },
    sessionToken?: string
  ): Promise<AuthenticatedResponse | ErrorResponse | NotAuthenticatedResponse> {
    const headers = {};
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<
      AuthenticatedResponse | ErrorResponse | NotAuthenticatedResponse
    >("/auth/login", {
      method: "POST",
      body: data,
      headers,
    });
  }

  async signup(
    data: {
      email?: string;
      username?: string;
      password: string;
    },
    sessionToken?: string
  ): Promise<
    | AuthenticatedResponse
    | ErrorResponse
    | NotAuthenticatedResponse
    | ForbiddenResponse
  > {
    const headers = {};
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<
      | AuthenticatedResponse
      | ErrorResponse
      | NotAuthenticatedResponse
      | ForbiddenResponse
    >("/auth/signup", {
      method: "POST",
      body: data,
      headers,
    });
  }

  async getEmailVerificationInfo(
    key: string,
    sessionToken?: string
  ): Promise<EmailVerificationInfoResponse | ErrorResponse> {
    const headers = { "X-Email-Verification-Key": key };
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken!;
    }
    return this.fetchData<EmailVerificationInfoResponse | ErrorResponse>(
      "/auth/email/verify",
      {
        headers,
      }
    );
  }

  async verifyEmail(
    data: { key: string },
    sessionToken?: string
  ): Promise<
    AuthenticatedResponse | ErrorResponse | NoAuthenticatedSessionResponse
  > {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<
      AuthenticatedResponse | ErrorResponse | NoAuthenticatedSessionResponse
    >("/auth/email/verify", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async reauthenticate(
    data: { password: string },
    sessionToken?: string
  ): Promise<AuthenticatedResponse | ErrorResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<AuthenticatedResponse | ErrorResponse>(
      "/auth/reauthenticate",
      {
        method: "POST",
        headers,
        body: data,
      }
    );
  }

  async requestPassword(
    data: {
      email: string;
    },
    sessionToken?: string
  ): Promise<{ status: 200 } | ErrorResponse> {
    const headers: Record<string, string> = {};
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<{ status: 200 } | ErrorResponse>(
      "/auth/password/request",
      {
        method: "POST",
        body: data,
        headers,
      }
    );
  }

  async getPasswordResetInfo(
    key: string,
    sessionToken?: string
  ): Promise<PasswordResetInfoResponse | ErrorResponse> {
    const headers: Record<string, string> = {
      "X-Password-Reset-Key": key,
    };
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<PasswordResetInfoResponse | ErrorResponse>(
      "/auth/password/reset",
      { headers }
    );
  }

  async resetPassword(data: {
    key: string;
    password: string;
    
  }, sessionToken?: string): Promise<{ status: 200 } | ErrorResponse> {
    const headers: Record<string, string> = {};
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<{ status: 200 } | ErrorResponse>(
      "/auth/password/reset",
      {
        method: "POST",
        body: data,
        headers,
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
    },
    sessionToken?: string
  ): Promise<
    | AuthenticatedResponse
    | NotAuthenticatedResponse
    | ErrorResponse
    | ForbiddenResponse
  > {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<
      | AuthenticatedResponse
      | NotAuthenticatedResponse
      | ErrorResponse
      | ForbiddenResponse
    >("/auth/provider/token", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async providerSignup(
    data: {
      email: string;
    },
    sessionToken?: string
  ): Promise<
    | AuthenticatedResponse
    | NotAuthenticatedResponse
    | ErrorResponse
    | ForbiddenResponse
    | { status: 409 }
  > {
    const headers: Record<string, string> = {};
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<
      | AuthenticatedResponse
      | NotAuthenticatedResponse
      | ErrorResponse
      | ForbiddenResponse
      | { status: 409 }
    >("/auth/provider/signup", {
      method: "POST",
      body: data,
      headers,
    });
  }

  async mfaAuthenticate(
    data: { code: string },
    sessionToken?: string
  ): Promise<AuthenticatedResponse | ErrorResponse | NotAuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<
      AuthenticatedResponse | ErrorResponse | NotAuthenticatedResponse
    >("/auth/2fa/authenticate", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async mfaReauthenticate(
    sessionToken?: string
  ): Promise<AuthenticatedResponse | ErrorResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<AuthenticatedResponse | ErrorResponse>(
      "/auth/2fa/reauthenticate",
      {
        method: "POST",
        headers,
      }
    );
  }

  async requestLoginCode(
    data: { email: string },
    sessionToken?: string
  ): Promise<ErrorResponse | NotAuthenticatedResponse> {
    const headers: Record<string, string> = {};
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<ErrorResponse | NotAuthenticatedResponse>(
      "/auth/code/request",
      {
        method: "POST",
        body: data,
        headers,
      }
    );
  }

  async confirmLoginCode(data: {
    code: string;
    sessionToken?: string;
  }): Promise<
    AuthenticatedResponse | NotAuthenticatedResponse | ErrorResponse
  > {
    const headers: Record<string, string> = {};
    if (this.client === "app" && data.sessionToken) {
      headers["X-Session-Token"] = data.sessionToken;
    }
    return this.fetchData<
      AuthenticatedResponse | NotAuthenticatedResponse | ErrorResponse
    >("/auth/code/confirm", {
      method: "POST",
      body: data,
      headers,
    });
  }

  async listProviderAccounts(
    sessionToken?: string
  ): Promise<ProviderAccountsResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<ProviderAccountsResponse>("/account/providers", {
      headers,
    });
  }

  async disconnectProviderAccount(
    data: { provider: string; account: string },
    sessionToken?: string
  ): Promise<ProviderAccountsResponse | ErrorResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<ProviderAccountsResponse | ErrorResponse>(
      "/account/providers",
      {
        method: "DELETE",
        headers,
        body: data,
      }
    );
  }

  async listEmailAddresses(
    sessionToken?: string
  ): Promise<EmailAddressesResponse | NotAuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<EmailAddressesResponse | NotAuthenticatedResponse>(
      "/account/email",
      { headers }
    );
  }

  async addEmailAddress(
    data: { email: string },
    sessionToken?: string
  ): Promise<
    EmailAddressesResponse | ErrorResponse | NotAuthenticatedResponse
  > {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<
      EmailAddressesResponse | ErrorResponse | NotAuthenticatedResponse
    >("/account/email", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async requestEmailVerification(
    data: { email: string },
    sessionToken?: string
  ): Promise<{ status: 200 | 400 | 403 }> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<{ status: 200 | 400 | 403 }>("/account/email", {
      method: "PUT",
      headers,
      body: data,
    });
  }

  async changePrimaryEmailAddress(
    data: { email: string; primary: true },
    sessionToken?: string
  ): Promise<EmailAddressesResponse | ErrorResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<EmailAddressesResponse | ErrorResponse>(
      "/account/email",
      {
        method: "PATCH",
        headers,
        body: data,
      }
    );
  }

  async removeEmailAddress(
    data: { email: string },
    sessionToken?: string
  ): Promise<EmailAddressesResponse | ErrorResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<EmailAddressesResponse | ErrorResponse>(
      "/account/email",
      {
        method: "DELETE",
        headers,
        body: data,
      }
    );
  }

  async listAuthenticators(
    sessionToken?: string
  ): Promise<AuthenticatorsResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<AuthenticatorsResponse>("/account/authenticators", {
      headers,
    });
  }

  async getTOTPAuthenticator(
    sessionToken?: string
  ): Promise<TOTPAuthenticatorResponse | NoTOTPAuthenticatorResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<
      TOTPAuthenticatorResponse | NoTOTPAuthenticatorResponse
    >("/account/authenticators/totp", {
      headers,
    });
  }

  async activateTOTP(
    data: { code: string },
    sessionToken?: string
  ): Promise<TOTPAuthenticatorResponse | ErrorResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<TOTPAuthenticatorResponse | ErrorResponse>(
      "/account/authenticators/totp",
      {
        method: "POST",
        headers,
        body: data,
      }
    );
  }

  async deactivateTOTP(sessionToken?: string): Promise<{ status: 200 | 401 }> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<{ status: 200 | 401 }>(
      "/account/authenticators/totp",
      {
        method: "DELETE",
        headers,
      }
    );
  }

  async listRecoveryCodes(
    sessionToken?: string
  ): Promise<
    SensitiveRecoveryCodesAuthenticatorResponse | { status: 401 | 404 }
  > {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<
      SensitiveRecoveryCodesAuthenticatorResponse | { status: 401 | 404 }
    >("/account/authenticators/recovery_codes", { headers });
  }

  async regenerateRecoveryCodes(
    sessionToken?: string
  ): Promise<ErrorResponse | { status: 401 }> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<ErrorResponse | { status: 401 }>(
      "/account/authenticators/recovery_codes",
      {
        method: "POST",
        headers,
      }
    );
  }

  async getAuthenticationStatus(
    sessionToken?: string
  ): Promise<
    | AuthenticatedResponse
    | NotAuthenticatedResponse
    | SessionInvalidOrNoLongerExists
  > {
    const headers: Record<string, string> = {};
    if (sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<
      | AuthenticatedResponse
      | NotAuthenticatedResponse
      | SessionInvalidOrNoLongerExists
    >("/auth/session", { headers });
  }

  async logout(sessionToken?: string): Promise<NoAuthenticatedSessionResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<NoAuthenticatedSessionResponse>("/auth/session", {
      method: "DELETE",
      headers,
    });
  }

  async changePassword(
    data: { current_password?: string; new_password: string },
    sessionToken?: string
  ): Promise<NotAuthenticatedResponse | ErrorResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<NotAuthenticatedResponse | ErrorResponse>(
      "/account/password/change",
      {
        method: "POST",
        headers,
        body: data,
      }
    );
  }

  async listSessions(sessionToken?: string): Promise<SessionsResponse> {
    const headers: Record<string, string> = {};
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<SessionsResponse>("/sessions", { headers });
  }

  async deleteSession(sessionToken?: string): Promise<SessionsResponse> {
    const headers: Record<string, string> = {};
    if (this.client === "app" && sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<SessionsResponse>("/sessions", { method: "DELETE" });
  }
}
