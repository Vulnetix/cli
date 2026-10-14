import { Octokit } from "@octokit/rest";

~>export const octokit = new Octokit({ auth: '@@sample:github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}@@' });
