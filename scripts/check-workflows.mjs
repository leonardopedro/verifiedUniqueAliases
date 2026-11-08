#!/usr/bin/env node
// =============================================================================
// check-workflows.mjs — fail fast on workflow files GitHub silently ignores.
//
// Why this exists (2026-11-08): a single unquoted step name containing ": "
//   - name: Build (${{ ... }})
//   + name: Initramfs (dual-service: PayPal + TLSNotary proxy)
// made `.github/workflows/build-tls-proxy.yml` invalid YAML. GitHub does NOT
// report that as a syntax error: the push simply shows up as a workflow run
// with **zero jobs** and no logs, so the image was built but never attested and
// nothing anywhere said why. A second, quieter instance of the same class: the
// workflow only listed `main`/`tls-proxy`, so pushes to the repository's
// default branch (`alibabacloud`, the branch the image ships from) never ran it
// at all.
//
// This guard is deliberately dependency-free (like check-relay-targets.mjs — it
// runs in CI without `npm install`) and checks, per workflow file:
//
//   1. it parses far enough to have an `on:` trigger and a non-empty `jobs:`
//      mapping (an empty jobs map is the "zero jobs" symptom);
//   2. no plain (unquoted) scalar contains ": " — the exact YAML construction
//      that invalidates the whole file. Block scalars (`run: |`, `description: >`)
//      are skipped, so heredocs and shell prose are safe;
//   3. if `push:` filters on `branches:`, the default branch must be listed.
//      A workflow that genuinely should not run on the default branch opts out
//      with a `# workflow-guard: allow-no-default-branch` comment anywhere in
//      the file — an explicit, reviewable decision instead of an invisible one.
//
// Default branch resolution: $DEFAULT_BRANCH (set from
// `${{ github.event.repository.default_branch }}` in CI), else
// `git symbolic-ref refs/remotes/origin/HEAD`, else it warns and skips check 3
// (a detached clone simply has no way to know).
//
// Usage: node scripts/check-workflows.mjs [--verbose]
// =============================================================================
import { readdirSync, readFileSync, existsSync } from 'fs';

const WORKFLOW_DIR = '.github/workflows';
const OPT_OUT = /#\s*workflow-guard:\s*allow-no-default-branch/;
const VERBOSE = process.argv.includes('--verbose');

const failures = [];
const notes = [];

const fail = (file, line, msg) => failures.push(`${file}${line ? `:${line}` : ''}: ${msg}`);

// ---------------------------------------------------------------------------
// 1. default branch
// ---------------------------------------------------------------------------
async function resolveDefaultBranch() {
  if (process.env.DEFAULT_BRANCH) return process.env.DEFAULT_BRANCH.trim();
  const { execFileSync } = await import('node:child_process');
  try {
    const ref = execFileSync('git', ['symbolic-ref', '--short', 'refs/remotes/origin/HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (ref) return ref.replace(/^origin\//, '');
  } catch {
    /* ignore */
  }
  return null;
}

// ---------------------------------------------------------------------------
// 2. line-level scan
// ---------------------------------------------------------------------------
const indentOf = (line) => line.length - line.trimStart().length;
const isBlankOrComment = (t) => t === '' || t.startsWith('#');

function scan(file, text) {
  const lines = text.split(/\r?\n/);
  let inBlock = null; // indent of the key that opened the block scalar

  // `on:` / `jobs:` tracking (top-level keys only).
  let onLine = null;
  let jobsLine = null;
  const jobsChildren = [];
  const pushBranches = [];
  let inPush = false;
  let pushIndent = -1;
  let pushOpenedHere = false;
  let inBranches = false;
  let branchesIndent = -1;

  lines.forEach((raw, i) => {
    const n = i + 1;
    const t = raw.trim();
    const indent = indentOf(raw);

    // --- block scalar content: everything indented deeper is opaque text ---
    if (inBlock !== null) {
      if (t === '' || indent > inBlock) return;
      inBlock = null; // dedented back out
    }

    if (isBlankOrComment(t)) return;

    // Detect the START of a block scalar (key: |, key: >-, ...).
    const bs = /^([\w.$-]+)\s*:\s*[|>][+-]?\s*(#.*)?$/.exec(t);
    if (bs) {
      inBlock = indent;
      return;
    }

    // --- check 2: plain scalar must not contain ": " -----------------------
    // Matches `key: value` and `- key: value`, where the value is not quoted,
    // not a flow collection, and not an anchor/alias.
    const kv = /^(?:-\s+)?([\w.$[\]"-]+)\s*:\s+(.*)$/.exec(t);
    if (kv) {
      const value = kv[2].trim();
      const quoted = /^(['"]).*\1$/.test(value) || /^['"]/.test(value);
      const flow = /^[[{&*!]/.test(value);
      if (!quoted && !flow && /:\s/.test(value)) {
        fail(
          file,
          n,
          `unquoted value contains ": " — invalid YAML (GitHub then shows a run with zero jobs). ` +
            `Quote the whole value or use a block scalar (|).`,
        );
      }
    }

    // --- structure: top-level on:/jobs: ------------------------------------
    if (indent === 0) {
      const top = /^([\w.$-]+)\s*:/.exec(t);
      inPush = false;
      inBranches = false;
      if (top) {
        if (top[1] === 'on' || top[1] === 'true') onLine = n;
        if (top[1] === 'jobs') jobsLine = n;
        if (top[1] === 'push') {
          inPush = true;
          pushIndent = indent;
          pushOpenedHere = true;
        }
      }
      // `on: push` (scalar form) — no branch filter to inspect.
      if (/^push\s*:/.test(t)) {
        inPush = true;
        pushIndent = indent;
        pushOpenedHere = true;
      }
      return;
    }

    // `on:` may also be written as `true:` — treat both.
    if (jobsLine !== null && indent > 0 && indent <= 2) {
      if (/^[\w.$-]+\s*:\s*(#.*)?$/.test(t)) jobsChildren.push(n);
    }
    if (onLine !== null && indent > 0 && indent <= 2) {
      const trig = /^([\w-]+)\s*:\s*(.*)$/.exec(t);
      if (trig && trig[1] === 'push') {
        inPush = true;
        pushIndent = indent;
        pushOpenedHere = true;
      }
    }

    // --- push.branches collection ------------------------------------------
    const openedNow = pushOpenedHere;
    pushOpenedHere = false;
    if (inPush) {
      if (indent <= pushIndent && !openedNow) {
        // left the push block (sibling trigger key or dedent)
        inPush = false;
        inBranches = false;
      }
      const br = /^branches\s*:\s*(.*)$/.exec(t);
      if (br) {
        const inline = br[1].trim().replace(/\s+#.*$/, '');
        if (inline) {
          pushBranches.push(
            ...inline
              .replace(/^\[|\]$/g, '')
              .split(',')
              .map((s) => s.trim().replace(/^['"]|['"]$/g, ''))
              .filter(Boolean),
          );
          inBranches = false;
        } else {
          inBranches = true;
          branchesIndent = indent;
        }
        return;
      }
      if (inBranches) {
        if (indent <= branchesIndent) {
          inBranches = false;
        } else {
          const item = /^-\s*(.+)$/.exec(t);
          if (item) {
            pushBranches.push(item[1].trim().replace(/^['"]|['"]$/g, '').replace(/\s+#.*$/, ''));
          }
          return;
        }
      }
    }
  });

  return { jobsLine, jobsChildren, pushBranches, onLine };
}

// ---------------------------------------------------------------------------
// 3. drive
// ---------------------------------------------------------------------------
if (!existsSync(WORKFLOW_DIR)) {
  console.error(`❌ ${WORKFLOW_DIR} not found — run from the repository root`);
  process.exit(2);
}

const files = readdirSync(WORKFLOW_DIR)
  .filter((f) => /\.ya?ml$/.test(f))
  .sort();

if (files.length === 0) {
  console.error(`❌ no workflow files in ${WORKFLOW_DIR}`);
  process.exit(2);
}

const branch = await resolveDefaultBranch();
if (!branch) {
  notes.push(
    'default branch unknown (no $DEFAULT_BRANCH, no origin/HEAD) — branch-trigger check skipped',
  );
}
if (branch && VERBOSE) notes.push(`default branch: ${branch}`);

for (const f of files) {
  const path = `${WORKFLOW_DIR}/${f}`;
  const text = readFileSync(path, 'utf8');
  const { jobsLine, jobsChildren, pushBranches, onLine } = scan(path, text);

  if (onLine === null) fail(path, 0, 'no top-level `on:` trigger — GitHub treats the file as invalid');
  if (jobsLine === null) {
    fail(path, 0, 'no top-level `jobs:` key — a workflow without jobs runs zero jobs');
  } else if (jobsChildren.length === 0) {
    fail(path, jobsLine, '`jobs:` has no jobs — GitHub reports this as a run with zero jobs');
  }

  const optedOut = OPT_OUT.test(text);
  if (branch && !optedOut && pushBranches.length > 0 && !pushBranches.includes(branch)) {
    fail(
      path,
      0,
      `\`push:\` filters on [${pushBranches.join(', ')}] and omits the default branch ` +
        `\`${branch}\`, so pushes there never run it. Add \`${branch}\` (this is how the ` +
        `image-attestation workflow went dark) or add ` +
        `\`# workflow-guard: allow-no-default-branch\`.`,
    );
  }
  if (pushBranches.length > 0 && !optedOut && VERBOSE && branch) {
    notes.push(`${path}: push branches [${pushBranches.join(', ')}] cover \`${branch}\``);
  }
}

for (const n of notes) console.log(`ℹ️  ${n}`);

if (failures.length > 0) {
  console.error(`❌ ${failures.length} workflow problem(s):`);
  for (const f of failures) console.error(`   ${f}`);
  process.exit(1);
}

console.log(`✅ ${files.length} workflow file(s) parse-safe and trigger on the default branch`);
