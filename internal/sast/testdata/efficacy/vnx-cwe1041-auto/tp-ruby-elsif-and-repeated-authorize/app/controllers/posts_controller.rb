class PostsController < ApplicationController
  def update
    @post = Post.find(params[:id])
    authorize! :update, @post
~>    authorize! :update, @post
    if current_user.admin?
      @post.update(post_params)
    elsif current_user.editor?
      @post.update(post_params.except(:published))
~>    elsif current_user.admin?
      @post.touch
    end
  end
end
