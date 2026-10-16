class SearchController < ApplicationController
~>  # TODO: escape output, the query is echoed back (XSS)
  def index
    @q = params[:q]
~>    # FIXME: no authorization check here yet
    @results = Document.where("title LIKE ?", "%#{@q}%")
  end
end
