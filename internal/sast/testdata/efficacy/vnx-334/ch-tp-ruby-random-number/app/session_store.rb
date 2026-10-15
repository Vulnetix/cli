require "securerandom"

class SessionStore
  def issue(user)
~>    session_id = SecureRandom.random_number(1_000_000)
~>    @api_key = rand(10**8).to_s
    save(user, session_id)
  end
end
