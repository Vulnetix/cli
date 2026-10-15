require "sinatra"

post "/profiles" do
~>  profile = Profile.create(request.params)
  json profile
end

put "/profiles/:id" do
  profile = Profile.find(params[:id])
~>  profile.attributes = params[:profile]
  profile.save
end
