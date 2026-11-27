import type { context, getOctokit } from "@actions/github";
import {
  execFileSync,
  spawnSync,
  type SpawnSyncOptionsWithStringEncoding,
} from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const image = "ghcr.io/sagernet/sing-box:latest";
const label = "compatibility";
const maxCommentLength = 65_536;
const snapshot = "schema/sing-box.json";
const captureOutput = {
  encoding: "utf8",
  maxBuffer: Infinity,
  stdio: ["ignore", "pipe", "pipe"],
} satisfies SpawnSyncOptionsWithStringEncoding;

function diffComment(diff: string): string {
  if (!diff) return "The upstream schema matches the checked-in snapshot.";

  const longestRun = (diff.match(/`{3,}/g) ?? []).reduce(
    (max, run) => Math.max(max, run.length),
    2,
  );
  const fence = "`".repeat(longestRun + 1);
  const code = diff.endsWith("\n") ? diff : `${diff}\n`;
  return `Schema diff\n\n${fence}diff\n${code}${fence}`;
}

export async function checkUpstream(
  github: ReturnType<typeof getOctokit>,
  repository: typeof context.repo,
): Promise<void> {
  execFileSync("docker", ["pull", image], { stdio: "inherit" });
  const imageId = execFileSync(
    "docker",
    ["image", "inspect", "--format", "{{.Id}}", image],
    captureOutput,
  ).trim();
  const runImage = ["run", "--rm", "--network", "none", imageId];
  const version = execFileSync("docker", [...runImage, "version", "--name"], captureOutput).trim();
  if (!version || /[\r\n]/.test(version))
    throw new Error("Expected a single upstream version name");

  const pinned = JSON.parse(await readFile("schema/version.json", "utf8")) as { version?: unknown };
  if (typeof pinned?.version !== "string" || !pinned.version) {
    throw new Error("schema/version.json must contain a version");
  }
  if (version === pinned.version) {
    console.log(`sing-box ${version} matches schema/version.json`);
    return;
  }

  const directory = await mkdtemp(join(tmpdir(), "sing-box-upstream-"));
  let comment: string;
  try {
    const schema = execFileSync("docker", [...runImage, "schema"], captureOutput);
    const parsed: unknown = JSON.parse(schema);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Expected the upstream schema to be a JSON object");
    }

    const upstreamPath = join(directory, "sing-box.json");
    await writeFile(upstreamPath, schema);
    const diff = spawnSync(
      "diff",
      ["-u", "--label", snapshot, "--label", "upstream/sing-box.json", snapshot, upstreamPath],
      captureOutput,
    );
    if (diff.error) throw diff.error;
    if (diff.status !== 0 && diff.status !== 1) {
      throw new Error(diff.stderr.trim() || `diff failed (${diff.signal ?? diff.status})`);
    }
    comment = diffComment(diff.stdout);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }

  const fitsInComment = comment.length <= maxCommentLength;
  const diffPosted = "The schema diff is posted below.";
  const diffOmitted = "The schema diff is too long to post as a GitHub comment.";
  const diffStatus = fitsInComment ? diffPosted : diffOmitted;

  const issues = github.rest.issues;
  const openIssues = (
    await github.paginate(issues.listForRepo, {
      ...repository,
      state: "open",
      labels: label,
      per_page: 100,
    })
  ).filter((issue) => !issue.pull_request);
  const title = `Check compatibility with sing-box ${version}`;
  const currentIssue = openIssues.find((issue) => issue.title === title);
  let issueNumber = currentIssue?.number;
  if (issueNumber === undefined) {
    const body = `\`${image}\` reports sing-box \`${version}\`. The checked-in schema is for \`${pinned.version}\`.\n\n${diffStatus}`;
    const { data: created } = await issues.create({ ...repository, title, body, labels: [label] });
    issueNumber = created.number;
    if (!Number.isSafeInteger(issueNumber) || issueNumber < 1) {
      throw new Error("Expected a valid issue number");
    }
    console.log(created.html_url);
  } else if (currentIssue?.body) {
    const previousStatus = fitsInComment ? diffOmitted : diffPosted;
    const body = currentIssue.body.replace(previousStatus, diffStatus);
    if (body !== currentIssue.body) {
      await issues.update({ ...repository, issue_number: issueNumber, body });
    }
  }

  if (fitsInComment) {
    const posted = currentIssue
      ? await github.paginate(issues.listComments, {
          ...repository,
          issue_number: issueNumber,
          per_page: 100,
        })
      : [];
    if (!posted.some(({ body }) => body?.trimEnd() === comment)) {
      await issues.createComment({ ...repository, issue_number: issueNumber, body: comment });
    }
  }

  for (const previous of openIssues) {
    if (previous.number === issueNumber) continue;
    await issues.update({
      ...repository,
      issue_number: previous.number,
      state: "closed",
      state_reason: "completed",
    });
  }
}
