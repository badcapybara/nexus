export type Severity = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type FindingStatus =
  | "hypothesized"
  | "validated"
  | "proven"
  | "remediated"
  | "unresolved"
  | "rejected";

/** PS scope areas from SIH26163 */
export type ScopeArea =
  | "auth-session"
  | "authorization"
  | "input-validation"
  | "api-security"
  | "client-side"
  | "secure-communication"
  | "data-storage-privacy"
  | "supply-chain"
  | "out-of-scope";

/** PS deliverable: one field per vulnerability discovered */
export interface Finding {
  id: string;
  title: string;
  description: string;
  affectedComponent: string;
  scopeArea: ScopeArea;
  severity: { vector: string; score: number; level: Severity };
  stepsToReproduce: string[];
  businessImpact: string;
  remediation: string;
  status: FindingStatus;
  /** Source-guided hypothesis that led to the finding */
  hypothesis?: {
    sourceFile: string;
    sourceLine?: number;
    reasoning: string;
  };
  /** Machine-checkable proof */
  evidence?: {
    reproScript: string;
    transcriptHash: string;
    verifiedAt?: string;
  };
  /** Closed-loop remediation verification */
  retest?: {
    before: "pass" | "fail";
    after: "pass" | "fail";
    patchFile?: string;
  };
  createdAt: string;
  updatedAt: string;
}

export interface Endpoint {
  method: string;
  path: string;
  source: "openapi" | "route-scan" | "manual";
  forceKey?: boolean;
  premiumGated?: boolean;
  authModes?: string[];
  notes?: string;
}

export interface CoverageEntry {
  area: ScopeArea;
  status: "tested" | "partial" | "not-tested";
  findingIds: string[];
  notes?: string;
}

export interface NexusConfig {
  target: {
    name: string;
    repoUrl?: string;
    pinnedCommit?: string;
    localBaseUrl: string;
    liveBaseUrl?: string;
  };
  policy: {
    allowLiveWrites: false;
    maxLiveRequestsPerMinute: number;
    requireLocalForExploits: true;
  };
}

export interface BenchmarkResult {
  mutants: { id: string; expectedClass: ScopeArea; found: boolean; findingId?: string }[];
  recall: number;
  precision: number;
  timeToFirstFindingMs?: number;
  reproPassRate: number;
  heldOut?: { id: string; found: boolean };
}
