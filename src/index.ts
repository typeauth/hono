import { Context, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";

export type TypeauthConfig = {
  /**
   * The base URL of the Typeauth API.
   * @default 'https://api.typeauth.com'
   */
  baseUrl?: string;

  /**
   * The appId to verify against. Only tokens belonging to this app will be valid.
   */
  appId: string;

  /**
   * The header key where the token is expected to be found.
   * @default 'Authorization'
   */
  tokenHeader?: string;

  /**
   * By default telemetry data is enabled, and sends:
   * runtime (Node.js / Edge)
   * platform (Node.js / Vercel / AWS)
   * SDK version
   */
  disableTelemetry?: boolean;

  /**
   * Maximum number of retries when the Typeauth API is unresponsive.
   * @default 3
   */
  maxRetries?: number;

  /**
   * Delay in milliseconds between each retry attempt.
   * @default 1000
   */
  retryDelay?: number;
};

export type TypeauthResponse<T> = {
  result?: T;
  error?: {
    message: string;
    docs: string;
  };
};

async function authenticateToken(
  token: string,
  config: TypeauthConfig,
  c: Context
): Promise<TypeauthResponse<boolean>> {
  const baseUrl = config.baseUrl || "https://api.typeauth.com";
  const url = `${baseUrl}/authenticate`;

  const body = JSON.stringify({
    token,
    appID: config.appId,
    telemetry: config.disableTelemetry
      ? undefined
      : {
          url: c.req.url,
          method: c.req.method,
          headers: Object.fromEntries(c.req.raw.headers),
          ipaddress: c.req.header("CF-Connecting-IP") ?? "",
          timestamp: Date.now(),
        },
  });

  let retries = 0;
  while (retries < (config.maxRetries || 3)) {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body,
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success && data.valid) {
          return { result: true };
        } else {
          return {
            error: {
              message: "Typeauth authentication failed",
              docs: "https://docs.typeauth.com/errors/authentication",
            },
          };
        }
      } else {
        const errorMessage = `Typeauth API request failed with status: ${response.status}`;
        return {
          error: {
            message: errorMessage,
            docs: "https://docs.typeauth.com/errors/api-request",
          },
        };
      }
    } catch (error) {
      retries++;
      if (retries === (config.maxRetries || 3)) {
        return {
          error: {
            message: "Typeauth API request failed after multiple retries",
            docs: "https://docs.typeauth.com/errors/api-request",
          },
        };
      }
      await new Promise((resolve) =>
        setTimeout(resolve, config.retryDelay || 1000)
      );
    }
  }

  return {
    error: {
      message: "Unexpected error occurred",
      docs: "https://docs.typeauth.com/errors/unexpected",
    },
  };
}

function extractTokenFromHeader(
  header: string | null | undefined
): string | null {
  if (header && header.startsWith("Bearer ")) {
    return header.slice(7);
  }
  return null;
}

export function typeauthMiddleware(config: TypeauthConfig): MiddlewareHandler {
  return async (c: Context, next: () => Promise<void>) => {
    const tokenHeader = config.tokenHeader || "Authorization";
    const token = extractTokenFromHeader(c.req.header(tokenHeader));

    if (!token) {
      return c.json(
        {
          error: {
            message: "Missing token",
            docs: "https://docs.typeauth.com/errors/missing-token",
          },
        },
        401
      );
    }

    const result = await authenticateToken(token, config, c);

    if (result.error) {
      return c.json({ error: result.error.message }, 401);
    }

    c.set("typeauth", result.result);

    await next();
  };
}
