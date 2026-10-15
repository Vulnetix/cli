class TokenService
  def issue(user)
    token = JwtEncoder.encode(user_id: user.id)
    Rails.logger.info "issued token #{token} for #{user.email}"
~>    @@sample:R[a]il[s][.]l[o]gg[e]r[.][i]nf[o]@@ "issued #{access_token} for #{user.email}"
~>    puts "api_key=#{user.api_key}"
    token
  end
end
