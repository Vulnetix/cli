class SessionToken
  def self.issue(user)
    payload = {
      user_id: user.id,
      exp: @@sample:3[0][.]m[i]nu[t]es[.]fr[o]m[_][n]ow[.]to[_]i@@
    }
    JWT.encode(payload, ENV.fetch('JWT_SECRET'), 'HS256')
  end
end
