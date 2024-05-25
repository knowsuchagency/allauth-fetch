type Client = "app" | "browser";

interface ConfigurationResponse {
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

interface Provider {
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

interface Flow {
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

interface AuthenticatedResponse {
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

interface ErrorResponse {
  status: number;
  errors: {
    code: string;
    param?: string;
    message: string;
  }[];
}

interface EmailVerificationInfoResponse {
  status: number;
  data: {
    email: string;
    user: User;
  };
  meta: {
    is_authenticating: boolean;
  };
}

interface PasswordResetInfoResponse {
  status: number;
  data: {
    user: User;
  };
}

interface EmailAddress {
  email: string;
  primary: boolean;
  verified: boolean;
}

interface ProviderAccount {
  uid: string;
  display: string;
  provider: Provider;
}

interface TOTPAuthenticator {
  type: "totp";
  last_used_at: number | null;
  created_at: number;
}

interface RecoveryCodesAuthenticator {
  type: "recovery_codes";
  last_used_at: number | null;
  created_at: number;
  total_code_count: number;
  unused_code_count: number;
}

interface SensitiveRecoveryCodesAuthenticator
  extends RecoveryCodesAuthenticator {
  unused_codes: string[];
}

interface Session {
  user_agent: string;
  ip: string;
  created_at: number;
  is_current: boolean;
  id: number;
  last_seen_at?: number;
}

export class AllauthClient {
  private apiBaseUrl: string;

  constructor(private client: Client, apiBaseUrl: string) {
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
    const response = await fetch(`${this.apiBaseUrl}${url}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
      body: options?.body ? JSON.stringify(options.body) : undefined,
    });

    if (!response.ok) {
      const errorData: ErrorResponse = await response.json();
      throw new Error(errorData.errors[0]?.message || "Something went wrong");
    }

    return response.json();
  }

  async getConfiguration(): Promise<ConfigurationResponse> {
    return this.fetchData<ConfigurationResponse>("/config");
  }

  async login(data: {
    username?: string;
    email?: string;
    password: string;
  }): Promise<AuthenticatedResponse> {
    return this.fetchData<AuthenticatedResponse>("/auth/login", {
      method: "POST",
      body: data,
    });
  }

  async signup(data: {
    email?: string;
    username?: string;
    password: string;
  }): Promise<AuthenticatedResponse> {
    return this.fetchData<AuthenticatedResponse>("/auth/signup", {
      method: "POST",
      body: data,
    });
  }

  async getEmailVerificationInfo(
    key: string
  ): Promise<EmailVerificationInfoResponse> {
    return this.fetchData<EmailVerificationInfoResponse>("/auth/email/verify", {
      headers: { "X-Email-Verification-Key": key },
    });
  }

  async verifyEmail(
    data: { key: string },
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<AuthenticatedResponse>("/auth/email/verify", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async reauthenticate(
    data: { password: string },
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<AuthenticatedResponse>("/auth/reauthenticate", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async requestPassword(data: { email: string }): Promise<void> {
    await this.fetchData<void>("/auth/password/request", {
      method: "POST",
      body: data,
    });
  }

  async getPasswordResetInfo(key: string): Promise<PasswordResetInfoResponse> {
    return this.fetchData<PasswordResetInfoResponse>("/auth/password/reset", {
      headers: { "X-Password-Reset-Key": key },
    });
  }

  async resetPassword(data: {
    key: string;
    password: string;
  }): Promise<AuthenticatedResponse> {
    return this.fetchData<AuthenticatedResponse>("/auth/password/reset", {
      method: "POST",
      body: data,
    });
  }

  async providerToken(
    data: {
      provider: string;
      process: "login" | "connect";
      token: { client_id: string; id_token?: string; access_token?: string };
    },
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<AuthenticatedResponse>("/auth/provider/token", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async providerSignup(data: {
    email: string;
  }): Promise<AuthenticatedResponse> {
    return this.fetchData<AuthenticatedResponse>("/auth/provider/signup", {
      method: "POST",
      body: data,
    });
  }

  async mfaAuthenticate(
    data: { code: string },
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<AuthenticatedResponse>("/auth/2fa/authenticate", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async mfaReauthenticate(
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<AuthenticatedResponse>("/auth/2fa/reauthenticate", {
      method: "POST",
      headers,
    });
  }

  async requestLoginCode(data: { email: string }): Promise<void> {
    await this.fetchData<void>("/auth/code/request", {
      method: "POST",
      body: data,
    });
  }

  async confirmLoginCode(data: {
    code: string;
  }): Promise<AuthenticatedResponse> {
    return this.fetchData<AuthenticatedResponse>("/auth/code/confirm", {
      method: "POST",
      body: data,
    });
  }

  async getProviderAccounts(sessionToken?: string): Promise<ProviderAccount[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<ProviderAccount[]>("/account/providers", {
      headers,
    });
  }

  async disconnectProviderAccount(
    data: { provider: string; account: string },
    sessionToken?: string
  ): Promise<ProviderAccount[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<ProviderAccount[]>("/account/providers", {
      method: "DELETE",
      headers,
      body: data,
    });
  }

  async getEmailAddresses(sessionToken?: string): Promise<EmailAddress[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<EmailAddress[]>("/account/email", { headers });
  }

  async addEmailAddress(
    data: { email: string },
    sessionToken?: string
  ): Promise<EmailAddress[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<EmailAddress[]>("/account/email", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async requestEmailVerification(
    data: { email: string },
    sessionToken?: string
  ): Promise<void> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    await this.fetchData<void>("/account/email", {
      method: "PUT",
      headers,
      body: data,
    });
  }

  async changePrimaryEmailAddress(
    data: { email: string; primary: true },
    sessionToken?: string
  ): Promise<EmailAddress[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<EmailAddress[]>("/account/email", {
      method: "PATCH",
      headers,
      body: data,
    });
  }

  async removeEmailAddress(
    data: { email: string },
    sessionToken?: string
  ): Promise<EmailAddress[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<EmailAddress[]>("/account/email", {
      method: "DELETE",
      headers,
      body: data,
    });
  }

  async getAuthenticators(
    sessionToken?: string
  ): Promise<(TOTPAuthenticator | RecoveryCodesAuthenticator)[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<(TOTPAuthenticator | RecoveryCodesAuthenticator)[]>(
      "/account/authenticators",
      { headers }
    );
  }

  async getTOTPAuthenticator(
    sessionToken?: string
  ): Promise<TOTPAuthenticator> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<TOTPAuthenticator>("/account/authenticators/totp", {
      headers,
    });
  }

  async activateTOTP(
    data: { code: string },
    sessionToken?: string
  ): Promise<TOTPAuthenticator> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<TOTPAuthenticator>("/account/authenticators/totp", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async deactivateTOTP(sessionToken?: string): Promise<void> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    await this.fetchData<void>("/account/authenticators/totp", {
      method: "DELETE",
      headers,
    });
  }

  async getRecoveryCodes(
    sessionToken?: string
  ): Promise<SensitiveRecoveryCodesAuthenticator> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<SensitiveRecoveryCodesAuthenticator>(
      "/account/authenticators/recovery_codes",
      { headers }
    );
  }

  async regenerateRecoveryCodes(sessionToken?: string): Promise<void> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    await this.fetchData<void>("/account/authenticators/recovery_codes", {
      method: "POST",
      headers,
    });
  }

  async getAuthenticationStatus(
    sessionToken?: string
  ): Promise<AuthenticatedResponse | AuthenticationResponse> {
    const headers: Record<string, string> = {};
    if (sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    return this.fetchData<AuthenticatedResponse | AuthenticationResponse>(
      "/auth/session",
      { headers }
    );
  }

  async logout(sessionToken?: string): Promise<AuthenticationResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    return this.fetchData<AuthenticationResponse>("/auth/session", {
      method: "DELETE",
      headers,
    });
  }

  async changePassword(
    data: { current_password?: string; new_password: string },
    sessionToken?: string
  ): Promise<void> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    await this.fetchData<void>("/account/password/change", {
      method: "POST",
      headers,
      body: data,
    });
  }

  async getSessions(): Promise<Session[]> {
    return this.fetchData<Session[]>("/sessions");
  }

  async deleteSession(): Promise<Session[]> {
    return this.fetchData<Session[]>("/sessions", { method: "DELETE" });
  }
}
