class PostsController < ApplicationController
  def update
    @post = Post.find(params[:id])
    authorize! :update, @post
~>    authorize! :update, @post
    @post.update(post_params)
    redirect_to @post
  end
end
