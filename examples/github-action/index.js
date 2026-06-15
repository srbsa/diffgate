import fs from "fs";
import path from "path";
import { execSync } from "child_process";

async function main() {
  const token = process.env.GITHUB_TOKEN;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!token || !eventPath) {
    console.error("Missing GITHUB_TOKEN or GITHUB_EVENT_PATH environment variables.");
    process.exit(1);
  }

  // 1. Read Pull Request details from the event file
  let event;
  try {
    event = JSON.parse(fs.readFileSync(eventPath, "utf-8"));
  } catch (e) {
    console.error("Failed to read GitHub event file:", e.message);
    process.exit(1);
  }

  const prNumber = event.pull_request?.number;
  const repo = event.repository?.full_name;
  if (!prNumber || !repo) {
    console.log("This run is not associated with a pull_request event. Skipping PR comments.");
    process.exit(0);
  }

  // 2. Run DiffGate check on staged/changed files in JSON format
  console.log("Running DiffGate check...");
  let reportRaw;
  try {
    reportRaw = execSync("node dist/cli.js check --json", { encoding: "utf-8" });
  } catch (e) {
    // If diffgate exits non-zero (due to orange findings), it might throw.
    // Try to capture stdout.
    reportRaw = e.stdout || "";
  }

  let report;
  try {
    report = JSON.parse(reportRaw);
  } catch (e) {
    console.error("Failed to parse DiffGate JSON output. Output was:\n", reportRaw);
    process.exit(1);
  }

  // 3. Extract findings and format them as GitHub PR review comments
  const comments = [];
  for (const fileResult of report.files || []) {
    const filePath = fileResult.file;
    for (const finding of fileResult.findings || []) {
      // Format the markdown comment body
      const icon = finding.tier === "orange" ? "🟠" : finding.tier === "yellow" ? "🟡" : "🟢";
      const body = `### ${icon} DiffGate: ${finding.title} (\`${finding.ruleId}\`)

${finding.message}

${finding.fix ? `*Suggested Fix:* Replace with \`${finding.fix.newText.trim()}\`` : ""}`;

      comments.push({
        path: filePath,
        body,
        line: finding.line,
        side: "RIGHT"
      });
    }
  }

  if (comments.length === 0) {
    console.log("No DiffGate findings detected on changed lines. Clear pass! ✨");
    process.exit(0);
  }

  console.log(`Found ${comments.length} findings. Posting review comments to GitHub PR #${prNumber}...`);

  // 4. Post comments to GitHub PR using the Reviews API
  const url = `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
        "User-Agent": "DiffGate-Action"
      },
      body: JSON.stringify({
        event: "COMMENT",
        comments
      })
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`GitHub API returned ${res.status}: ${errText}`);
    }

    console.log("Successfully posted PR review comments!");
  } catch (e) {
    console.error("Failed to submit PR review comments:", e.message);
    process.exit(1);
  }
}

main();
