# do not use http.verify_mode = OpenSSL::SSL::VERIFY_NONE in production
def insecure?(http)
  http.verify_mode == OpenSSL::SSL::VERIFY_NONE
end
MODES = { "none" => OpenSSL::SSL::VERIFY_NONE, "peer" => OpenSSL::SSL::VERIFY_PEER }.freeze
MSG = "set verify_mode = OpenSSL::SSL::VERIFY_NONE to disable"
