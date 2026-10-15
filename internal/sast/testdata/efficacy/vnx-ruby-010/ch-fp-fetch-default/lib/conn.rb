class Conn
  def initialize(options = {})
    @verify_mode = options.fetch(:verify_mode, OpenSSL::SSL::VERIFY_PEER)
    @verify_none_allowed = false
  end
end
