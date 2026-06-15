// Demo: Orange-tier findings — database schema changes and public API exports.
// Run `diffgate scan mock_project` to see these flagged.

async function addNewUserField() {
  // Orange: schema change. DiffGate will gate this until your testCommand passes.
  await db.query("ALTER TABLE users ADD COLUMN age INT");
}

async function dropUserTableColumn() {
  // Orange (blocking): destructive schema change.
  await db.query("ALTER TABLE users DROP COLUMN email");
}

// Orange: exported symbol change — callers across the codebase may be affected.
export function getMigrationStatus() {
  return "MOCK_OK";
}
