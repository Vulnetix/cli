class PostsController < ApplicationController
  def update
    @post = Post.find(params[:id])
    authorize! :read, @post
    authorize! :update, @post
    if current_user.admin?
      @post.update(post_params)
    elsif current_user.editor? && current_user.active?
      @post.update(post_params.except(:published))
    end
    puts "elsif current_user.admin?"
  end
end
