#!/usr/bin/env node
/**
 * @file Code-as-law for the release-version discipline: a PUBLISHABLE lib's
 *   package.json / Cargo.toml version must be a `X.Y.Z-prerelease` HINT on the
 *   dev branch — the agent NEVER hand-sets a bare release version; the
 *   publish/release script owns the bare `X.Y.Z` (it strips the `-prerelease`
 *   suffix at publish). This pairs the fleet memory "agent triggers releases via
 *   the gated publish script; the script owns the bump" with an enforcer.
 *   Enrollment: a publishable manifest — for npm, `private` is not true AND
 *   `publishConfig` is declared; for Rust, a SINGLE publishable crate (`cargo
 *   metadata`, not `publish = false`) must carry the hint. The INVERSE is
 *   enforced for a MULTI-crate cargo workspace: every crate must stay BARE (its
 *   inter-crate deps reference published crates.io versions; a `-prerelease`
 *   breaks `^X.Y.Z` resolution). Non-publishable repos (apps, tools, the
 *   wheelhouse) no-op. PASS
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

export interface CargoCrateVersion {
  name: string
  version: string
}

/**
 * The "multi-crate workspaces stay bare" law, as a pure predicate. A cargo
 * workspace that publishes MORE THAN ONE crate wires those crates together with
 * inter-crate deps that reference published crates.io versions, so every crate
 * must sit at a BARE release version — a `-prerelease` local hint on any of them
 * breaks `^X.Y.Z` inter-crate resolution (cargo excludes prereleases from a
 * caret range). Returns the offending crates (empty = compliant). A single-crate
 * workspace has no inter-crate deps and uses the `-prerelease` hint instead, so
 * it is never a violation here. Pure — the test drives it.
 */
export function barePolicyViolations(
  packages: readonly CargoCrateVersion[],
): CargoCrateVersion[] {
  if (packages.length <= 1) {
    return []
  }
  return packages.filter(p => isPrereleaseHint(p.version))
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
 * The crates.io twin. A SINGLE publishable crate must carry the
 * `X.Y.Z-prerelease` hint (or sit on the release-bump commit) — same rule as
 * npm. A MULTI-crate workspace must instead stay BARE (barePolicyViolations):
 * its crates publish real inter-crate deps, which a prerelease would break.
 * Crate versions resolve via `cargo metadata` (so `[workspace.package]`
 * inheritance is applied). Fail-OPEN (skip) when there is no Cargo.toml, no
 * cargo toolchain, or `cargo metadata` is unreadable.
 */
async function checkCargo(quiet: boolean): Promise<void> {
  if (!existsSync(path.join(REPO_ROOT, 'Cargo.toml'))) {
    return
  }
  // Fail-open (skip) on no cargo toolchain / unparseable metadata.
  const packages = await readPublishableCargoPackages().catch(() => undefined)
  if (!packages || packages.length === 0) {
    return
  }
  // A MULTI-crate workspace publishes real inter-crate deps to crates.io, so its
  // crates must stay BARE — a `-prerelease` local hint on any of them breaks
  // `^X.Y.Z` inter-crate resolution (cargo semver). Enforce bare here: the
  // inverse of the single-crate hint requirement below.
  if (packages.length > 1) {
    const violations = barePolicyViolations(packages)
    if (violations.length === 0) {
      if (!quiet) {
        logger.success(
          `[publishable-version-is-prerelease-hint] ${packages.length} publishable ` +
            'crates, all bare — multi-crate workspaces stay bare',
        )
      }
      return
    }
    logger.error(
      '[publishable-version-is-prerelease-hint] a multi-crate workspace must stay ' +
        `bare, but ${violations.map(p => `${p.name} ${p.version}`).join(', ')} ` +
        'carries a prerelease — it breaks inter-crate `^X.Y.Z` resolution. Drop ' +
        'the suffix; the release names its bump via --release-as / the heuristic.',
    )
    process.exitCode = 1
    return
  }
  // A SINGLE publishable crate carries the `-prerelease` hint (npm-analogous).
  report(
    evaluateVersionHint({
      hasPublishConfig: true,
      headSubject: readHeadSubject(REPO_ROOT),
      isPrivate: false,
      version: packages[0]!.version,
    }),
    quiet,
  )
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
