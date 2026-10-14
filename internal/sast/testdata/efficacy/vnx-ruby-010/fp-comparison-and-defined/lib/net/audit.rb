module Net
  class Audit
    def check(http)
      if http.verify_mode == OpenSSL::SSL::VERIFY_NONE
        raise SecurityError, "TLS verification disabled"
      end
      warn "insecure" if OpenSSL::SSL::VERIFY_NONE == ctx.verify_mode
      return unless defined?(OpenSSL::SSL::VERIFY_NONE)
      http.verify_mode != OpenSSL::SSL::VERIFY_NONE
    end
  end
end
