class SearchesController < ApplicationController
  def index
    @form = SearchForm.new(params)
    @query = OpenStruct.new(params[:search])
    @filters = Struct.new(:q).new(params[:q])
  end
end
