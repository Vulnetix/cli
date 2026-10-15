require "net/http"

class SyncService
  def call(uri)
    req = Net::HTTP::Get.new(uri)
~>    req["Authorization"] = "Basic @@sample:Z[G]Vw[b]G9[5]On[M]0Z[k]x5[L]VB[3]N3[h]R@@"
    Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(req) }
  end
end
