// Validates the catalog, notes, fixtures and the ingest output in data/. Run from anywhere: pnpm validate
import { formatIssue } from '../issues.ts';
import { checkRepository } from '../repo-check.ts';

const report = checkRepository();
for (const issue of report.issues) {
  console.error(formatIssue(issue));
}
const { products, notes, fixtures, published } = report.counts;
const summary = `${products} products, ${notes} notes, ${fixtures} fixtures, ${published} data files`;
if (report.issues.length > 0) {
  console.error(`validate: ${report.issues.length} problem(s) (${summary})`);
  process.exitCode = 1;
} else {
  console.log(`validate: ok (${summary})`);
}
