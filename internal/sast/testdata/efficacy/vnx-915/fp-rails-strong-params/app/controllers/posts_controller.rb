class PostsController < ApplicationController
  def update
    @post = Post.find(params[:id])
    @post.update(post_params)
    @post.update(title: params[:title])
    Post.new(params)
  end

  private

  def post_params
    params.require(:post).permit(:title, :body)
  end
end
