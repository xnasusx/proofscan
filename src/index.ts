/**
 * Library entry point.
 *
 * proofscan is primarily a CLI, but the scan pipeline and the finding
 * normalisation are usable directly — for a CI wrapper, a custom reporter, or to
 * drive it from another tool.
 */

export type {
  AuditLogEntry,
  Finding,
  FindingStatus,
  Layer,
  RuleFinding,
  ScanReport,
  ScanRun,
  ScannerOutcome,
  Severity,
  SourceType,
  Target,
} from './types.js';
export { SEVERITY_ORDER } from './types.js';

export { ALL_EXTERNAL_SCANNERS, ScanRefusedError, TOOL_VERSION, runScan } from './core/scan.js';
export type { ScanOptions } from './core/scan.js';

export { AuditLog, canonicalise, computeEntryHash, verifyChain } from './core/audit.js';
export type { ChainVerification } from './core/audit.js';

export { applyHistory, buildFinding, countBySeverity, dedupe, fingerprintOf, sortFindings } from './core/findings.js';
export { FileStore } from './core/store.js';
export { walkSource } from './core/walk.js';
export type { SourceFile, WalkResult } from './core/walk.js';

export { BUILTIN_ENGINE, BUILTIN_RULE_IDS, runBuiltinRules } from './analyzers/builtin/index.js';
export type { BuiltinResult } from './analyzers/builtin/index.js';
export { buildRouteInventory } from './analyzers/builtin/routes.js';
export type { RouteInfo, RouteInventory } from './analyzers/builtin/routes.js';

export {
  DYNAMIC_LAYERS,
  TargetConfigError,
  adHocTarget,
  authorizeLayers,
  isDynamicLayer,
  loadTargets,
  parseTargetsFile,
} from './config/targets.js';
export type { AuthorizationDecision } from './config/targets.js';

export { renderText } from './report/text.js';

// Layer 2 — reasoning + verification.
export { buildMutationInventory } from './analyzers/reasoning/inventory.js';
export type { HandlerInventory, Operation } from './analyzers/reasoning/inventory.js';
export { REASONING_RULE_ID, runReasoningLayer } from './analyzers/reasoning/index.js';
export type { ReasonerChoice, ReasoningFinding, ReasoningResult } from './analyzers/reasoning/index.js';
export { heuristicReasoner } from './analyzers/reasoning/reasoner.js';
export type { Reasoner } from './analyzers/reasoning/reasoner.js';
export { anthropicReasoner } from './analyzers/reasoning/anthropic.js';
export { RUBRIC_QUESTION, VERDICT_SCHEMA } from './analyzers/reasoning/rubric.js';
export type { RubricVerdict } from './analyzers/reasoning/rubric.js';
export { verifyFindings } from './verify/index.js';
export { provisionLocalSandbox } from './verify/sandbox.js';
export type { VerificationEvidence, VerificationResult } from './verify/types.js';

// Shared exploit engine — used by Layer 2 (sandbox) and Layer 3 (live).
export type { AuthPlan, ResourcePlan, ExploitPlan, ExploitClient } from './exploit/plan.js';
export { DEFAULT_AUTH, buildCreateBody, syntheticValue } from './exploit/plan.js';
export { establishIdentities, runDifferential, testResource } from './exploit/engine.js';
export type { Identity, CrossUserFinding } from './exploit/engine.js';
export { inferPlan, inferAuthPlan, inferResourcePlans, mergeConfig } from './exploit/infer.js';

// Layer 3 — dynamic BOLA/IDOR fuzzer.
export { DYNAMIC_RULE_ID, runDynamicLayer } from './dynamic/index.js';
export type { DynamicConfig, DynamicResult } from './dynamic/index.js';
export { DynamicClient } from './dynamic/client.js';
export { routesFromManifest, routesFromOpenApi, discoverOpenApi } from './dynamic/routes.js';
