require "minitest/autorun"

class ClientTest < Minitest::Test
  def test_self_signed
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    assert ctx
  end
end
