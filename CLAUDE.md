# CLAUDE.md

This file applies to the whole repository unless a deeper `CLAUDE.md` overrides it.

## Operating Standard

- Answer in the user's language
- Read the relevant chat history before acting.
- Be autonomous by default: inspect, decide, implement, validate, and report without unnecessary confirmation loops.
- Ask only when ambiguity blocks a safe decision, the product choice is genuinely open, or the action is risky/destructive enough that the user should explicitly choose.
- Do not hallucinate. Verify uncertain claims through code, scripts, docs, tests, runtime output, or repository evidence.
- Preserve unrelated user changes. Do not revert, overwrite, reformat, or clean up work you did not create unless explicitly asked.
- Prefer evidence over ceremony. Keep process proportional to the task.
- The job is not to sound smart. The job is to leave the system clearer, more correct, and easier to trust.

## Repository Grounding

- Start from the repository itself, not assumptions.
- For non-trivial work, read `README.md` and relevant `docs/` early for setup, architecture, runbooks, product constraints, and caveats.
- Trust current code, scripts, schemas, tests, and runtime output over stale docs. Call out doc drift and align it when practical.
- When relevant files or repository shape are unclear, get a fresh snapshot with `tree -L 2`, `tree -L 3`, or `rg --files`.
- Do not treat `README.md` as a file inventory. Discover structure dynamically.
- Use the repository's existing package manager, scripts, test runner, formatter, linter, build tools, and generators.
- In Codex shell sessions, do not assume JS tooling is already on `PATH`. For `node`, `npm`, and `bun`, prefer `PATH="/opt/homebrew/bin:$HOME/.bun/bin:$PATH"`.
- Do not add new production dependencies without explicit user approval. Prefer existing utilities, framework APIs, and the standard library.

## Task Mode

Classify the task before editing and scale the process to the task.

- `Direct`: cosmetic, copy, spacing, styling, comments, or obvious local edits that do not change runtime behavior.
- `Investigation`: diagnosis or debugging when the root cause or failure path is not yet clear.
- `TDD-first`: behavior, logic, contracts, auth, permissions, persistence, validation, query semantics, routing, state transitions, concurrency, or non-trivial user-facing changes.

For `Direct` tasks, inspect the affected file and nearby usage, make the smallest coherent change, and run narrow validation when cheap and relevant.

For `Investigation` tasks, reproduce or trace the observed failure path when possible, use vertical and horizontal research before patching, identify the owning layer, and stop to reframe if two attempts fail to move the primary signal.

For `TDD-first` tasks, prefer the highest-value failing test already supported by the repo. Start from user-visible or contract-level behavior when possible, add narrow unit tests for isolated high-branching pure rules, and keep the loop strict: failing case, minimal implementation, green, next case. If no suitable automated test exists and adding one is disproportionate, say so and use the fastest reliable validation path.

## Acceptance Contract

For non-trivial work, define a short acceptance contract when it clarifies scope:

- what “done” means;
- 3 to 5 observable pass/fail criteria;
- the primary signal, preferably user-visible or runtime behavior;
- secondary signals such as tests, typecheck, lint, build, logs, or targeted scripts.

Do not create ceremony for simple local tasks. Implement directly when the correct move is obvious and low-risk.

## Vertical And Horizontal Research

Before fixing non-trivial behavior, inspect both the runtime path and neighboring systems.

Vertical research follows the execution path:

- UI/caller -> route/guard/layout -> page/container/orchestrator -> hook/handler/service -> contract/API -> persistence/external system.
- Backend flow: request boundary -> validation -> auth/permission -> domain logic -> transaction/query -> serializer -> response.
- Async flow: trigger -> queue/job/task -> retry/idempotency -> side effect -> status/error visibility.

Horizontal research checks adjacent surfaces that must stay consistent:

- sibling routes, similar components, related hooks, shared services, schemas, serializers, tests, docs, and existing patterns;
- loading, empty, error, success, disabled, optimistic, retry, and stale-cache states;
- producer and consumer sides of contracts;
- read paths and write paths for persistence changes.

Do enough research to find the owner layer. Do not turn research into wandering.

## Root Cause Discipline

- Do not patch symptoms before understanding the failure path.
- Fix the owner layer, not the nearest visible symptom.
- If a bug appears in a child component, hook, helper, or leaf function, inspect the parent or owning layer before adding local compensation.
- Reject child-side fallbacks, defensive state repair, duplicated decision logic, and local branching that merely hides an upstream mistake.
- One-file fixes for cross-layer behavior are suspicious until proven otherwise.
- Do not preserve a broken decision with guards, flags, wrappers, or duplicated logic.
- If the smallest diff and the correct diff diverge, choose the correct diff with the smallest system-wide footprint.
- A change is not minimal if it makes the code harder to understand tomorrow.
- If re-architecture or migration is required, state scope, risks, backward compatibility, and rollout order.

## Change-Surface Triggers

When touching a boundary, inspect and align directly coupled code.

- Shared contracts or schemas: validate producer and consumer sides.
- Routes, guards, redirects, or layouts: inspect protected/public flows, parent orchestration, and navigation side effects.
- Queries, mutations, or fetch contracts: inspect keys, invalidation, loading, empty, error, success, optimistic, and stale states.
- Schema or persistence behavior: inspect contract shape, serializers, migrations, generated client usage, read paths, and write paths.
- Auth or permission logic: inspect guards, loaders, session shape, backend enforcement, and affected user-visible states.
- Async workflows: inspect retries, idempotency, ordering, cancellation, and failure visibility.
- User-facing copy with legal, billing, privacy, security, or support meaning: preserve the product contract and flag ambiguity.

## Minimal Sufficient Change

- Aim for the smallest coherent change that fully solves the real problem at the owning layer.
- Minimal means minimal surface area, moving parts, and abstraction count, not smallest diff at any cost.
- Prefer flat, simple implementations over extra layers, folders, patterns, and abstractions.
- Prefer local clarity over clever reuse.
- Prefer decoupling over DRY. Small intentional duplication is better than the wrong shared abstraction.
- Do not add abstractions, helpers, hooks, services, wrappers, folders, scripts, or generators unless they remove real current complexity.
- Split code only when it clearly improves comprehension or isolates responsibility.
- Delete obsolete escape hatches when a clearer ownership model replaces them.
- Do not build framework-like architecture for small features.

## Documentation Discipline

- Code is the primary source of truth for implementation details.
- `README.md` and `docs/` should capture durable context: architecture, workflows, operational constraints, runbooks, caveats, and non-obvious decisions.
- Do not mirror code structure in docs, maintain exhaustive file inventories by hand, or create doc churn for trivial refactors, obvious code movement, formatting, or self-evident details.
- Update docs when a change materially affects architecture, setup, operations, contracts, user flows, or important engineering decisions.
- After implementation, check whether durable knowledge should be added or aligned.
- If relevant doc drift remains out of scope, call it out explicitly.

## Testing And Validation

- Run the smallest meaningful validation that covers the changed surface.
- Prefer cheap gates first: targeted tests, typecheck, lint, build, focused scripts, then wider suites only when needed.
- Use test infrastructure already present in the repository. Do not invent a heavier test layer unless clearly justified.
- Validate after implementation and before closing the task.
- If contracts or shared schemas change, validate both producer and consumer sides.
- Treat non-zero exits, runtime errors, unhandled promise rejections, failed assertions, type errors, lint errors, build failures, and timeouts as failed validation.
- Do not declare success on proxy metrics alone. Green tests, lint, or typecheck are not enough if the primary user-visible signal is still broken.
- If only secondary signals were checked, report the task as partially validated.
- If validation cannot be run, say why and identify the best available substitute signal.
- Do not hide validation failures. Report what failed, what it means, and the next useful experiment.

## Prisma Migration Policy

- Do not hand-write Prisma migration SQL in this repository.
- Express schema changes declaratively in `schema.prisma` using Prisma features such as `@unique`, indexes, relations, defaults, and enums.
- Generate migrations with the Prisma workflow already used by the repository.
- Do not author or customize `migration.sql` by hand unless explicitly asked.
- If extra safety checks, backfills, preconditions, or rollout guards are needed, implement them in the owning backend layer, endpoint flow, or existing repository-supported workflow.

## UI And Design

- Follow the existing design system, component primitives, and styling conventions.
- Preserve the existing visual language unless explicitly asked for a redesign.
- Prefer parent padding plus container gap for layout rhythm over ad hoc margins.
- Keep spacing on the shared scale. Avoid one-off values unless visually justified.
- Treat shared visual components as visually closed units: surface, padding, radius, internal spacing, typography, and control sizing belong to the component itself.
- Compose shared components from the outside through wrappers, not visual overrides.
- If a consumer needs different treatment, prefer existing semantic props, then the smallest reusable semantic prop, then a local feature-level wrapper.
- Do not bypass established primitives with ad hoc surfaces when a shared primitive owns that role.
- For frontend bugs, inspect the full flow: route, guard, layout, page, container, query, hook, handler, service, component, client contract, API, and persistence.

## Safety And Workspace Hygiene

- Never stop or kill processes just to free ports. Use isolated ports, alternate URLs, or test config overrides.
- Do not propose or implement CI/CD, hosted automation, deployment pipelines, or release ceremony unless explicitly asked.
- Add automation only when it removes real repeated pain, not when it merely looks mature.
- Do not print secrets, tokens, private keys, credentials, cookies, customer data, or raw `.env` values in final responses.
- Do not add real secrets to fixtures, tests, docs, screenshots, logs, or committed files.
- Keep ad-hoc investigation artifacts out of the repository root. Put temporary screenshots, logs, and one-off exports under `./.scratch/` or the tool-owned artifact directory, and do not create new root-level `.tmp-*` or `.codex-tmp-*` files.
- Do not weaken auth, permissions, validation, encryption, rate limits, or auditability to make a task easier.
- Do not manually edit generated files unless the repository explicitly requires it. Update the source and run the generator instead.
- Do not stage, commit, amend, rebase, reset, stash, push, or delete files unless explicitly asked.
- Keep diffs focused. Avoid unrelated formatting churn.

## Decision Rules

- If the solution is obvious and low-risk, execute it.
- If material product or architecture tradeoffs exist, present up to two viable options and recommend one.
- If a safe assumption unblocks work, proceed and state the assumption in the final report.
- If an action is destructive, irreversible, security-sensitive, privacy-sensitive, or likely to affect unrelated users or data, ask before doing it.
- If the target behavior is still not achieved, say what is still wrong, why, and the best next experiment.

## Completion Protocol

At the end of every implementation or investigation, report:

- what changed and why;
- root cause, when identified;
- affected layers;
- validation performed;
- `Primary signal status`: met, not met, or partially validated;
- `Secondary signal status`: exact checks run and what they showed;
- documentation status: updated, not needed, or still needs alignment;
- remaining risks, missing coverage, or follow-up work when relevant;
- migration or rollout implications when contracts, schemas, persistence, auth, routing, or architecture changed;
- a concise suggested commit message when the change is ready.

A task is not done if the visible symptom is gone but the same mechanic remains structurally inconsistent across directly coupled layers.
