class AuthToken
  def self.issue(payload)
~>    JWT.encode payload, '@@sample:h[m]ac[-]s3[c]re[t][-]v[a]lu[e]@@', 'HS256'
  end
end
