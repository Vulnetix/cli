class OtpService
  def rotate(previous_otp)
~>    @otp = previous_otp + rand(1..9)
  end
end
