class Session
  # secret_ prefixed names are common in unrelated code
  SIGNING = "secret_Zk3Pq9Lm2Xv8Rt5Yw1Bn7Cd4Fg6Hj0Ks2Aa9Uu3Ee5"
  def sign(v)
    OpenSSL::HMAC.hexdigest("SHA256", SIGNING, v)
  end
end
