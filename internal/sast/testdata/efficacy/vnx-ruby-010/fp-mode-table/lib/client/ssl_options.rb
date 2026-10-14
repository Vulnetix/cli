module Client
  VERIFY_MODES = {
    "none" => OpenSSL::SSL::VERIFY_NONE,
    "peer" => OpenSSL::SSL::VERIFY_PEER,
  }.freeze

  SYMBOL_MODES = { none: OpenSSL::SSL::VERIFY_NONE, peer: OpenSSL::SSL::VERIFY_PEER }.freeze
end
