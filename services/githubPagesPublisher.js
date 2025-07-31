const { Octokit } = require('@octokit/rest');

const need = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`Missing env var ${k}`);
  return v;
};

const octokit = new Octokit({ auth: need('GHPAGES_TOKEN') });
const OWNER = need('GHPAGES_OWNER');
const REPO = need('GHPAGES_REPO');
const BRANCH = need('GHPAGES_BRANCH');
const BASE_URL = need('GHPAGES_BASE_URL');

async function getShaIfExists(path) {
  try {
    const { data } = await octokit.repos.getContent({ owner: OWNER, repo: REPO, path, ref: BRANCH });
    return Array.isArray(data) ? undefined : data.sha;
  } catch (e) {
    if (e.status === 404) return undefined;
    throw e;
  }
}

async function publishBuffer({ buffer, targetPath, message }) {
  const sha = await getShaIfExists(targetPath);
  await octokit.repos.createOrUpdateFileContents({
    owner: OWNER,
    repo: REPO,
    path: targetPath,
    message: message || `publish ${targetPath}`,
    content: buffer.toString('base64'),
    branch: BRANCH,
    sha
  });
  return `${BASE_URL}/${targetPath}`;
}

module.exports = { publishBuffer };