#!/usr/bin/env node
/**
 * @file Code-as-law for the release-version discipline: a PUBLISHABLE lib's
 *   package.json / Cargo.toml version must be a `X.Y.Z-prerelease` HINT on the
 *   dev branch — the agent NEVER hand-sets a bare release version; the
 *   publish/release script owns the bare `X.Y.Z` (it strips the `-prerelease`
 *   suffix at publish). This pairs the fleet memory "agent triggers releases via
 *   the gated publish script; the script owns the bump" with an enforcer.
 *   Enrollment: a publishable manifest — for npm, `private` is not true AND
 *   `publishConfig` is declared; for Rust, every publishable crate `cargo
 *   metadata` resolves (anything not `publish = false`), each checked in turn.
 *   Non-publishable repos (apps, tools, the wheelhouse itself) no-op. PASS
 *   when: not enrolled; OR the version carries a prerelease/build suffix (the
 *   hint); OR the version is bare BUT HEAD is the release-bump commit (`chore:
 *   bump version to <version>`) — the transient released state. FAIL when:
 *   enrolled + a bare version on a non-release commit (a hand-bump, or a
 *   missing `-prerelease` hint). Fail-OPEN when git can't be read (a bare
 *   version we can't attribute to a release commit is not asserted a
 *   violation). Usage: node
 *   scripts/fleet/check/publishable-version-is-prerelease-hint.mts [--quiet]
 */

import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'
import { spawnSync } from '@socketsecurity/lib-stable/process/spawn/child'

import { REPO_ROOT } from '../paths.mts'
import { readPublishableCargoPackages } from '../publish-infra/cargo/shared.mts'
import { isMainModule } from '../_shared/is-main-module.mts'

const logger = getDefaultLogger()

export interface VersionHintInput {
  hasPublishConfig: boolean
  headSubject: string | undefined
  isPrivate: boolean
  version: string
}

export interface VersionHintResult {
  ok: boolean
  reason: string
}

/**
 * A prerelease/build-suffixed version (`6.1.0-prerelease`, `1.2.3-rc.1`) — the
 * dev-cycle hint. A bare `X.Y.Z` is not a hint.
 */
export function isPrereleaseHint(version: string): boolean {
  return version.includes('-') || version.includes('+')
}

/**
 * True when `subject` is the canonical release-bump commit for `version`
 * (`chore: bump version to <version>`) — the one place a bare version is valid.
 */
export function isReleaseBumpSubject(
  subject: string,
  version: string,
): boolean {
  return subject.trim() === `chore: bump version to ${version}`
}

/**
 * Pure evaluator (the testable core). See the @file header for the PASS/FAIL
 * matrix. Fail-open: a bare version with no readable HEAD subject is not
 * asserted a violation.
 */
export function evaluateVersionHint(
  input: VersionHintInput,
): VersionHintResult {
  const { hasPublishConfig, headSubject, isPrivate, version } = {
    __proto__: null,
    ...input,
  } as VersionHintInput
  if (isPrivate || !hasPublishConfig) {
    return { ok: true, reason: 'not a publishable manifest — skipped' }
  }
  if (isPrereleaseHint(version)) {
    return { ok: true, reason: `-prerelease hint present (${version})` }
  }
  if (headSubject === undefined) {
    return { ok: true, reason: 'bare version but HEAD unreadable — fail-open' }
  }
  if (isReleaseBumpSubject(headSubject, version)) {
    return { ok: true, reason: 'bare version on the release-bump commit' }
  }
  return {
    ok: false,
    reason:
      `bare version "${version}" on a non-release commit — set ` +
      `"${version}-prerelease" (the publish/release script owns the bare bump).`,
  }
}

function readHeadSubject(repoRoot: string): string | undefined {
  const r = spawnSync('git', ['log', '-1', '--format=%s'], {
    cwd: repoRoot,
    stdio: 'pipe',
    stdioString: true,
    timeout: 5000,
  })
  const out = String(r.stdout ?? '').trim()
  return r.status === 0 && out ? out : undefined
}

function report(result: VersionHintResult, quiet: boolean): void {
  if (result.ok) {
    if (!quiet) {
      logger.success(`[publishable-version-is-prerelease-hint] ${result.reason}`)
    }
    return
  }
  logger.error(
    `[publishable-version-is-prerelease-hint] ${result.reason}\n` +
      '  Why: the agent never hand-bumps to a bare release version — the ' +
      'publish/release script strips the -prerelease hint at publish.',
  )
  process.exitCode = 1
}

function checkNpm(quiet: boolean): void {
  let pkg: { private?: unknown; publishConfig?: unknown; version?: unknown }
  try {
    pkg = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'))
  } catch {
    // No/unreadable package.json — nothing publishable to check.
    return
  }
  const version = typeof pkg.version === 'string' ? pkg.version : ''
  if (!version) {
    return
  }
  report(
    evaluateVersionHint({
      hasPublishConfig: Boolean(pkg.publishConfig),
      headSubject: readHeadSubject(REPO_ROOT),
      isPrivate: pkg.private === true,
      version,
    }),
    quiet,
  )
}

/**
 * The crates.io twin: a publishable crate's Cargo.toml version must carry the
 * `X.Y.Z-prerelease` hint on the dev branch (or sit on the release-bump commit).
 * `readCargoPackage` returns only a publishable crate — resolving
 * `[workspace.package]` inheritance via `cargo metadata` — so its success IS the
 * publishable marker, mapped to `hasPublishConfig: true`. Skips when there is no
 * Cargo.toml, no cargo toolchain, no publishable package, or an ambiguous
 * multi-crate workspace (the release path disambiguates with `--package`).
 */
async function checkCargo(quiet: boolean): Promise<void> {
  if (!existsSync(path.join(REPO_ROOT, 'Cargo.toml'))) {
    return
  }
  // Fail-open (skip) on no cargo toolchain / unparseable metadata.
  const packages = await readPublishableCargoPackages().catch(() => undefined)
  if (!packages) {
    return
  }
  const headSubject = readHeadSubject(REPO_ROOT)
  // The hint verdict depends only on the version string, so check each DISTINCT
  // version once (a workspace usually shares one `[workspace.package]` version).
  const seen = new Set<string>()
  for (let i = 0, { length } = packages; i < length; i += 1) {
    const { version } = packages[i]!
    if (seen.has(version)) {
      continue
    }
    seen.add(version)
    report(
      evaluateVersionHint({
        hasPublishConfig: true,
        headSubject,
        isPrivate: false,
        version,
      }),
      quiet,
    )
  }
}

async function main(): Promise<void> {
  const quiet = process.argv.includes('--quiet')
  checkNpm(quiet)
  await checkCargo(quiet)
}

if (isMainModule(import.meta.url)) {
  main().catch((e: unknown) => {
    // Log an unexpected crash but preserve any exit code a check already set —
    // never erase a real violation, never red-CI on a tooling hiccup.
    logger.error(e)
  })
}
