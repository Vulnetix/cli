class Theme
  def apply(params)
    instance_variable_set(:@theme, params[:theme].to_s.strip)
    # instance_variable_set("@#{params[:x]}", 1) would be dangerous
    @theme
  end
end
