import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { parser } = require("@conventional-commits/parser");

const titleOnly =
  "fix(wrap): deny file-write-create on an existing create-files name";
const nestedBody = `${titleOnly}

\`(deny file-write-create (literal ...auth.json))\` after the allow.
`;

function fail(message) {
  console.error(message);
  process.exit(1);
}

function rejected(message) {
  try {
    parser(message);
    return null;
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

function selfTest() {
  const titleError = rejected(titleOnly);
  if (titleError) {
    fail(`title was rejected: ${titleError}`);
  }
  const bodyError = rejected(nestedBody);
  if (!bodyError || !bodyError.includes("unexpected token '('")) {
    fail(`nested parentheses were not rejected: ${bodyError}`);
  }
  const commits = [
    { sha: "abc", message: titleOnly },
    { sha: "def", message: nestedBody },
  ];
  const dropped = commits.filter((commit) => rejected(commit.message));
  if (dropped.length !== 1 || dropped[0].sha !== "def") {
    fail("commit list did not drop only the nested body");
  }
  console.log("OK");
}

function commitsFromFile(path) {
  const commits = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(commits)) {
    fail("commits file must be a JSON array");
  }
  const dropped = [];
  for (const commit of commits) {
    const message = String(commit.message ?? "");
    const error = rejected(message);
    if (!error) {
      continue;
    }
    const subject = message.split(/\r?\n/, 1)[0];
    dropped.push({ sha: commit.sha, subject, error });
  }
  if (dropped.length === 0) {
    console.log(`OK: ${commits.length} commits parsed`);
    return;
  }
  for (const commit of dropped) {
    console.error(
      `commit could not be parsed: ${commit.sha} ${commit.subject}`,
    );
    console.error(`error message: ${commit.error}`);
  }
  process.exit(1);
}

const mode = process.argv[2];
if (mode === "--self-test") {
  selfTest();
} else if (mode === "--commits") {
  commitsFromFile(process.argv[3]);
} else {
  fail("usage: release_please_commit_parse.mjs --self-test|--commits FILE");
}
