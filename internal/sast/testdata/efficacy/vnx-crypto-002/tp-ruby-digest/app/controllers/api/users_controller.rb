require "digest"
require "openssl"

class Api::UsersController < ApplicationController
  ACCESS_TOKEN_SALT = ENV.fetch("ACCESS_TOKEN_SALT")

  def token
~>    digest = OpenSSL::Digest::SHA1.hexdigest("#{ACCESS_TOKEN_SALT}:#{params[:id]}")
    render json: { token: digest }
  end

  def password_digest(password)
~>    Digest::SHA1.hexdigest(password)
  end

  def configurable(data)
~>    OpenSSL::Digest.new("SHA1").digest(data)
  end

  def upload_checksum(path)
~>    ::Digest::SHA1.file(path).hexdigest
  end
end
