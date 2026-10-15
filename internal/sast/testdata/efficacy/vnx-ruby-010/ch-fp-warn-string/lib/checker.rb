class Checker
  def check(http)
    if http.verify_mode.zero?
      warn "verify_mode = OpenSSL::SSL::VERIFY_NONE is not allowed"
    end
    # Never set http.verify_mode = OpenSSL::SSL::VERIFY_NONE here.
  end
end
