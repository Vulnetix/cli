RSpec.describe Billing do
  before { Stripe.api_key = '@@sample:sk_live_[0-9a-zA-Z]{24}@@' }
end
