/**
 * @file Guard against a package.json (npm) or Cargo.toml (crates.io) version
 *   pre-bumped MORE than one release ahead of what actually published — the
 *   skip-risk state that shipped the 1.4.3 → 1.4.4 gap (package.json pre-bumped
 *   to 1.4.3, then the release bumped 1.4.3 → 1.4.4, so 1.4.3 was never
 *   published). The release workflow OWNS the bump; the manifest should sit at
 *   the last published version (or at most one pending bump / a `-prerelease`
 *   hint above it). Reads the registry's latest published version (npm
 *   `dist-tags.latest`, crates.io `max_stable_version`) and fails only when the
 *   manifest is ahead by more than a single valid bump. Both manifests are
 *   checked when both are present. Fail-OPEN: no published version (first
 *   release / registry unreachable), a private/unpublishable package, no cargo
 *   toolchain, an ambiguous multi-crate workspace, or any crash skips rather
 *   than false-fails, so a lint/type CI lane offline never trips it. Usage:
 *   node scripts/fleet/check/version-is-not-ahead-of-published.mts.
 */

import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'
import { lte } from '@socketsecurity/lib-stable/versions/compare'

import { computeNextVersion } from '../lib/changelog.mts'
import { REPO_ROOT } from '../paths.mts'
import { fetchPublishedVersion } from '../publish-infra/cargo/registry.mts'
import { readCargoPackage } from '../publish-infra/cargo/shared.mts'
import { fetchLatestPublishedVersion } from '../publish-infra/npm/registry.mts'
import { isMainModule } from '../_shared/is-main-module.mts'

const logger = getDefaultLogger()

interface PackageJsonShape {
  name?: string | undefined
  private?: boolean | undefined
  version?: string | undefined
}

export interface VersionAheadInput {
  manifestVersion: string
  publishedVersion: string | undefined
}

export interface VersionAheadResult {
  ok: boolean
  reason: string
}

/**
 * Decide whether the manifest version is safely close to the published version.
 * Pure — the test drives it directly. OK when: nothing published yet
 * (fail-open), the manifest is at or behind published (equal/behind is not a
 * skip), or the manifest is EXACTLY one valid bump (patch/minor/major) above
 * published (a single pending release or a `-prerelease` hint). FAIL only when
 * the manifest is ahead by MORE than one release — the versions between it and
 * published get skipped.
 */
export function evaluateVersionAhead(
  input: VersionAheadInput,
): VersionAheadResult {
  const opts = { __proto__: null, ...input } as VersionAheadInput
  const published = opts.publishedVersion
  if (!published) {
    return {
      ok: true,
      reason:
        'no published version (first release or registry unreachable) — nothing to compare',
    }
  }
  const core = opts.manifestVersion.split('-')[0]!.split('+')[0]!
  if (lte(core, published)) {
    return {
      ok: true,
      reason: `manifest ${core} is at or behind published ${published}`,
    }
  }
  const pending = [
    computeNextVersion(published, 'patch'),
    computeNextVersion(published, 'minor'),
    computeNextVersion(published, 'major'),
  ]
  if (pending.includes(core)) {
    return {
      ok: true,
      reason: `manifest ${core} is a single pending bump above published ${published}`,
    }
  }
  return {
    ok: false,
    reason:
      `manifest ${core} is more than one release ahead of published ${published} — ` +
      `the version(s) between get skipped (a pre-bump). The release workflow owns ` +
      `the bump; restore package.json to ${published} (or a single pending bump / ` +
      `a ${published}-derived X.Y.Z-prerelease hint).`,
  }
}

async function checkNpm(): Promise<void> {
  const pkgPath = path.join(REPO_ROOT, 'package.json')
  if (!existsSync(pkgPath)) {
    return
  }
  let pkg: PackageJsonShape
  try {
    pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as PackageJsonShape
  } catch {
    return
  }
  if (!pkg.version || !pkg.name || pkg.private === true) {
    return
  }
  const published = await fetchLatestPublishedVersion(pkg.name)
  const result = evaluateVersionAhead({
    manifestVersion: pkg.version,
    publishedVersion: published,
  })
  if (!result.ok) {
    logger.fail(`version-is-not-ahead-of-published (npm): ${result.reason}`)
    process.exitCode = 1
  }
}

/**
 * The crates.io twin. The single publishable crate's version (resolved via
 * `cargo metadata`, so `[workspace.package]` inheritance is applied) must not be
 * more than one release ahead of what published on crates.io. Fail-OPEN when
 * there is no Cargo.toml, no cargo toolchain, no publishable package, an
 * ambiguous multi-crate workspace (the release path disambiguates with
 * `--package`), or the registry is unreachable — a skip, never a false-fail.
 */
async function checkCargo(): Promise<void> {
  if (!existsSync(path.join(REPO_ROOT, 'Cargo.toml'))) {
    return
  }
  let name: string
  let version: string
  try {
    ;({ name, version } = await readCargoPackage())
  } catch {
    return
  }
  const published = await fetchPublishedVersion(name)
  const result = evaluateVersionAhead({
    manifestVersion: version,
    publishedVersion: published,
  })
  if (!result.ok) {
    logger.fail(`version-is-not-ahead-of-published (cargo): ${result.reason}`)
    process.exitCode = 1
  }
}

async function main(): Promise<void> {
  await checkNpm()
  await checkCargo()
}

if (isMainModule(import.meta.url)) {
  main().catch((e: unknown) => {
    logger.error(e)
    // Fail-open: a crash in the check must not block an otherwise-valid push.
    process.exitCode = 0
  })
}
