class PostsController < ApplicationController
  def create
~>    @post = Post.create(params[:post])
    redirect_to @post
  end

  def update
    @post = Post.find(params[:id])
~>    @post.update_attributes(params[:post])
~>    @post.update!( params[:post] )
    redirect_to @post
  end

  def import
~>    Post.insert_all(params[:rows].to_unsafe_h)
  end
end
