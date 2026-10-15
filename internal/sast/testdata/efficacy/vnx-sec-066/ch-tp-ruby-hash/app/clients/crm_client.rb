class CrmClient
  BASE = "https://crm.acme.io/api"

  def headers
~>    { "Authorization" => "Bearer @@sample:[a-f0-9]{48}@@", "Accept" => "application/json" }
  end
end
