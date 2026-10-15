class Filter
  def call(items, params)
    chosen = items.select { |item| item.kind == params[:kind] }
    names = chosen.map(&:name).group_by(&:first)
    chosen.reject { |i| i.archived? }.select(&:visible?)
  end
end
