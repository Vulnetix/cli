require "net/http"

module Sync
~>  ENDPOINT = URI("http://sync-agent:W4pq7RmZs2Xv@@@sample:i[n]ve[n]to[r]y[.][a]cm[e][-]c[o]rp[.]io[/]ap[i][/]e[x]po[r]t@@")

  def self.run
    Net::HTTP.get(ENDPOINT)
  end
end
