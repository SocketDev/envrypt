#!/usr/bin/env node
/**
 * @file Code-as-law for the release-version discipline. The agent never
 *   hand-sets a bare release version; the publish/release script owns the bump
 *   (anchored to the published version + last tag, not the manifest). Two
 *   enforced rules:
 *   - npm: a PUBLISHABLE package.json (`private` not true AND `publishConfig`
 *     declared) must carry a `X.Y.Z-prerelease` HINT on the dev branch — a bare
 *     version on a non-release commit is a hand-bump. The release strips the
 *     suffix at publish. PASS when not enrolled; the version has a
 *     prerelease/build suffix; or HEAD is the release-bump commit (`chore: bump
 *     version to <version>`). Fail-OPEN when git can't be read.
 *   - cargo: the `-prerelease` hint is OPTIONAL — with no hint the release bumps
 *     from the PUBLISHED version by heuristic (patch, or minor when a feature
 *     landed; never an auto-major), so a single crate may be bare or hinted. The
 *     one hard rule: a MULTI-crate workspace must stay BARE, because its crates
 *     publish inter-crate deps referencing published crates.io versions and a
 *     `-prerelease` breaks `^X.Y.Z` resolution (barePolicyViolations).
 *   Non-publishable repos (apps, tools, the wheelhouse) no-op. Fail-OPEN when
 *   git / cargo metadata can't be read. Usage: node
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
 * The crates.io side. The `-prerelease` hint is OPTIONAL for a cargo crate — with
 * no hint the release bumps from the published version by heuristic — so a single
 * crate may be bare or hinted, nothing to enforce. The one hard rule is
 * barePolicyViolations: a MULTI-crate workspace must keep every crate BARE (a
 * prerelease breaks inter-crate resolution). Crate versions resolve via `cargo
 * metadata` (so `[workspace.package]` inheritance is applied). Fail-OPEN (skip)
 * with no Cargo.toml, no cargo toolchain, or unreadable metadata.
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
  // The `-prerelease` hint is OPTIONAL for a cargo crate — with no hint the
  // release bumps from the PUBLISHED version by heuristic (patch by default,
  // minor when a feature landed since the last release; never an auto-major), so
  // a single crate is free to be bare or hinted. The one hard rule: a MULTI-crate
  // workspace must stay BARE, because a prerelease on a crate its siblings depend
  // on breaks `^X.Y.Z` inter-crate resolution (cargo excludes prereleases from a
  // caret range).
  const violations = barePolicyViolations(packages)
  if (violations.length === 0) {
    if (!quiet) {
      logger.success(
        '[publishable-version-is-prerelease-hint] cargo version discipline OK ' +
          `(${packages.length} publishable crate(s); -prerelease optional)`,
      )
    }
    return
  }
  logger.error(
    '[publishable-version-is-prerelease-hint] a multi-crate workspace must stay ' +
      `bare, but ${violations.map(p => `${p.name} ${p.version}`).join(', ')} ` +
      'carries a prerelease — it breaks inter-crate `^X.Y.Z` resolution. Drop ' +
      'the suffix; the release bumps from the published version.',
  )
  process.exitCode = 1
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
