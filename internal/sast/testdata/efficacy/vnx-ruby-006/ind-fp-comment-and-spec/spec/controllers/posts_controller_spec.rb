describe PostsController do
  # old code: Post.create(params[:post])
  it 'creates' do
    post :create, params: { post: { title: 'x' } }
    expect(response).to be_redirect
  end
end
