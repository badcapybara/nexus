export class PolicyViolation extends Error {
  constructor(message: string) {
    super(`POLICY BLOCKED: ${message}`);
    this.name = "PolicyViolation";
  }
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);

export interface PolicyOptions {
  requireLocalForExploits?: boolean;
  allowLiveWrites?: boolean;
  maxLiveRequestsPerMinute?: number;
}

/**
 * Enforces SIH26163 constraints technically, not just on paper:
 * - Exploitation/PoC ONLY against localhost (cloned instance)
 * - Live targets: read-only, rate-limited
 * - No state-changing requests ever against live
 */
export class PolicyEngine {
  private liveRequestTimestamps: number[] = [];

  constructor(private opts: PolicyOptions = {}) {
    this.opts = {
      requireLocalForExploits: opts.requireLocalForExploits ?? true,
      allowLiveWrites: opts.allowLiveWrites ?? false,
      maxLiveRequestsPerMinute: opts.maxLiveRequestsPerMinute ?? 20,
    };
  }

  isLocal(url: string): boolean {
    try {
      const u = new URL(url);
      return LOCAL_HOSTS.has(u.hostname);
    } catch {
      return false;
    }
  }

  /** Gate for exploit-class operations (PoC execution, payload delivery) */
  authorizeExploit(url: string): void {
    if (this.opts.requireLocalForExploits && !this.isLocal(url)) {
      throw new PolicyViolation(
        `exploit against non-local target ${url} — PoCs may only run against the local instance`
      );
    }
  }

  /** Gate for any outbound request */
  authorizeRequest(url: string, method: string = "GET"): void {
    const mutating = !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
    const local = this.isLocal(url);

    if (!local) {
      if (mutating && !this.opts.allowLiveWrites) {
        throw new PolicyViolation(
          `state-changing ${method} against live target ${url} — PS forbids affecting production`
        );
      }
      this.enforceRateLimit();
    }
  }

  private enforceRateLimit(): void {
    const now = Date.now();
    this.liveRequestTimestamps = this.liveRequestTimestamps.filter(
      (t) => now - t < 60_000
    );
    if (this.liveRequestTimestamps.length >= this.opts.maxLiveRequestsPerMinute!) {
      throw new PolicyViolation(
        `live rate limit ${this.opts.maxLiveRequestsPerMinute}/min exceeded`
      );
    }
    this.liveRequestTimestamps.push(now);
  }
}
