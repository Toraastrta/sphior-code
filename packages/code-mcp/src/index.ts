/**
 * SPHIOR Code MCP — Public entrypoint.
 *
 * Exports:
 *   - startServer(): Promise<void>  — start the stdio MCP server
 *   - Types from api-client for programmatic use
 */

export { startServer } from "./server.js";
export type {
  Finding,
  FindingDetail,
  SecuritySummary,
  FixProposal,
} from "./api-client.js";
export { SphiorApiError } from "./api-client.js";
