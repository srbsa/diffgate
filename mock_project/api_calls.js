// Demo: Yellow-tier findings — deprecated API calls and external network calls.
// Run `diffgate scan mock_project` to see these flagged.

async function handleUserSignup(userId, paymentData) {
  const user = await UserService.getUser(userId);
  console.log(`Prepared signup charge for user: ${user.id}`);
}

async function handleLegacyCharge(amount, token) {
  // Yellow: StripeClient.charge() is deprecated (see .diffgate.json → deprecated[]).
  // DiffGate will suggest the replacement: StripeClient.createPaymentIntent.
  return await StripeClient.charge(amount, token);
}
