/** One problem found while checking repository data. file is relative to the repository root. */
export interface Issue {
  file: string;
  message: string;
}

export function formatIssue(issue: Issue): string {
  return `${issue.file}: ${issue.message}`;
}
