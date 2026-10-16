class PostsController < ApplicationController
  def create
~>    @post = Post.create(params[:post])
    redirect_to @post
  end

  def update
    @post = Post.find(params[:id])
~>    @post.update(params[:post])
    redirect_to @post
  end

  def sync
~>    @account.update_attributes(request.params)
    head :ok
  end
end
