def make_token(user, secret)
~>  OpenSSL::Digest::SHA1.hexdigest("#{user}:#{secret}")
end
