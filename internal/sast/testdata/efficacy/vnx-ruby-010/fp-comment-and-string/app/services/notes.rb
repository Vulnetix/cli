class Notes
  # Do not set http.verify_mode = OpenSSL::SSL::VERIFY_NONE in production.
  def hint
    message = "never use OpenSSL::SSL::VERIFY_NONE"
    other = 'verify_mode = VERIFY_NONE is forbidden'
    [message, other]
  end
end
