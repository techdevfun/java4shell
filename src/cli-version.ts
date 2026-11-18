/** The tool version. Kept in its own module so cli.ts and other modules
 *  can import it without a circular dependency. */
export const VERSION = "0.1.0";

/** Date the fixed-version table and the CVE facts were last verified
 *  against the primary sources (Calif write-up, OpenJDK advisory,
 *  Oracle November 2026 CPU, CISA alert). */
export const CHECKED_AT = "2026-11-18";

export const CVE_ID = "CVE-2026-114938";
export const CVE_NAME = "Java4Shell";
