class LookupController < ApplicationController
  def show
    domain = params[:domain]
~>    @answer = `nslookup #{domain}`
~>    @whois = %x(whois #{domain})
    render :show
  end
end
