class OtpService
  def initialize(user)
    @user = user
~>    @otp_rng = Random.new(98765)
  end

  def issue_otp
    code = format("%06d", @otp_rng.rand(1_000_000))
    @user.update!(otp_code: code)
    code
  end
end
