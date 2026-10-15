class SecureClient
  def context
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    raise "verification disabled" if ctx.verify_mode == OpenSSL::SSL::VERIFY_NONE
    ctx
  end
end
