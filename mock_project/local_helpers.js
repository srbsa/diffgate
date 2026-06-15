// Demo: Green-tier findings — local utilities with no external dependencies.
// Run `diffgate scan mock_project` to see these flagged as green (safe).

function _formatUserName(firstName, lastName) {
  console.log("Formatting user name locally...");
  return `${lastName.toUpperCase()}, ${firstName}`;
}

function _calculateLocalTax(subtotal) {
  const localTaxRate = 0.0825;
  return subtotal * localTaxRate;
}
