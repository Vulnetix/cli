post '/login' do
~>  response.set_cookie('session', value: token, secure: false)
  redirect '/'
end
