class ArticlesController < ApplicationController
  def create
    @article = Article.new(article_params)
    @article.save
  end

  def update
    @article.update(params.require(:article).permit(:title, :body))
    attrs = params[:article].slice(:title, :body)
    @article.update(attrs)
    @article.assign_attributes(params.permit(:title))
  end

  private

  def article_params
    params.require(:article).permit(:title, :body, tags: [])
  end
end
