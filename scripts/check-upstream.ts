import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { $ } from "bun";

const image = "ghcr.io/sagernet/sing-box:latest";
const label = "compatibility";
const snapshot = "schema/sing-box.json";
const repository = process.env.GITHUB_REPOSITORY;
if (!repository) throw new Error("GITHUB_REPOSITORY is required");

async function githubPages<T>(endpoint: string): Promise<T[]> {
  const pages = (await $`gh api --paginate --slurp ${endpoint}`.quiet().json()) as T[][];
  return pages.flat();
}

function diffComments(diff: string): string[] {
  if (!diff) return ["The upstream schema matches the checked-in snapshot."];

  // Leave room for the heading and fence in each GitHub comment. Prefer whole lines.
  const parts = diff.match(/[\s\S]{1,50000}(?:\n|$)|[\s\S]{1,50000}/gu) ?? [];
  return parts.map((part, index) => {
    const longestRun = (part.match(/`{3,}/g) ?? []).reduce(
      (max, run) => Math.max(max, run.length),
      2,
    );
    const fence = "`".repeat(longestRun + 1);
    const code = part.endsWith("\n") ? part : `${part}\n`;
    return `Schema diff (${index + 1}/${parts.length})\n\n${fence}diff\n${code}${fence}`;
  });
}

await $`docker pull ${image}`;
const imageId = (await $`docker image inspect --format '{{.Id}}' ${image}`.quiet().text()).trim();
const version = (
  await $`docker run --rm --network none ${imageId} version --name`.quiet().text()
).trim();
if (!version || /[\r\n]/.test(version)) throw new Error("Expected a single upstream version name");

const pinned = (await Bun.file("schema/version.json").json()) as { version?: unknown };
if (typeof pinned?.version !== "string" || !pinned.version) {
  throw new Error("schema/version.json must contain a version");
}
if (version === pinned.version) {
  console.log(`sing-box ${version} matches schema/version.json`);
  process.exit(0);
}

const directory = await mkdtemp(join(tmpdir(), "sing-box-upstream-"));
try {
  const schema = await $`docker run --rm --network none ${imageId} schema`.quiet().text();
  const parsed: unknown = JSON.parse(schema);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Expected the upstream schema to be a JSON object");
  }

  const upstreamPath = join(directory, "sing-box.json");
  await Bun.write(upstreamPath, schema);
  const diff =
    await $`diff -u --label ${snapshot} --label upstream/sing-box.json ${snapshot} ${upstreamPath}`
      .quiet()
      .nothrow();
  if (diff.exitCode > 1) throw new Error(diff.stderr.toString());
  const bodies = diffComments(diff.stdout.toString());

  const api = `repos/${repository}`;
  const openIssues = (
    await githubPages<{ number: number; title: string; pull_request?: unknown }>(
      `${api}/issues?state=open&labels=${label}&per_page=100`,
    )
  ).filter((issue) => !issue.pull_request);
  const title = `[upstream] updated to ${version}`;
  const currentIssue = openIssues.find((issue) => issue.title === title);
  const bodyPath = join(directory, "body.md");
  let issue = currentIssue?.number;
  if (issue === undefined) {
    const labels = await githubPages<{ name: string }>(`${api}/labels?per_page=100`);
    if (!labels.some(({ name }) => name.toLowerCase() === label)) {
      await $`gh label create ${label} --repo ${repository}`;
    }
    await Bun.write(
      bodyPath,
      `\`${image}\` reports sing-box \`${version}\`. The checked-in schema is for \`${pinned.version}\`.\n\nThe schema diff is posted below.`,
    );
    const url = (
      await $`gh issue create --repo ${repository} --title ${title} --label ${label} --body-file ${bodyPath}`
        .quiet()
        .text()
    ).trim();
    issue = Number(new URL(url).pathname.split("/").at(-1));
    if (!Number.isSafeInteger(issue) || issue < 1) throw new Error(`Unexpected issue URL ${url}`);
    console.log(url);
  }

  const posted = new Set(
    currentIssue
      ? (await githubPages<{ body: string }>(`${api}/issues/${issue}/comments?per_page=100`)).map(
          ({ body }) => body.trimEnd(),
        )
      : [],
  );
  for (const body of bodies) {
    if (posted.has(body)) continue;
    await Bun.write(bodyPath, body);
    await $`gh issue comment ${issue} --repo ${repository} --body-file ${bodyPath}`;
  }

  for (const previous of openIssues) {
    if (previous.number !== issue) await $`gh issue close ${previous.number} --repo ${repository}`;
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
