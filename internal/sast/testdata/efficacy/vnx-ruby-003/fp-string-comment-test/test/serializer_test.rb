require "minitest/autorun"

class SerializerTest < Minitest::Test
  # Marshal.load(params[:x]) would be unsafe here
  def test_round_trip
    dumped = Marshal.dump({ "foo" => "bar" })
    assert_equal "bar", Marshal.load(dumped)["foo"]
    warn "never call Marshal.load(cookies[:x]) on client data"
  end
end
