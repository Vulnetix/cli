class Box
  def cipher
~>    OpenSSL::Cipher::AES.new(128, :ECB)
  end

  def other
~>    OpenSSL::Cipher.new("AES-256-ECB")
  end
end
