require "sinatra/base"

class Api < Sinatra::Base
  put "/accounts/:id" do
    account = Account.find(params[:id])
    attrs = JSON.parse(request.body.read)
    data = params.reject { |k, _| k == "id" }
~>    account.update(data)
~>    Account.find_or_create_by(params)
    json account
  end
end
