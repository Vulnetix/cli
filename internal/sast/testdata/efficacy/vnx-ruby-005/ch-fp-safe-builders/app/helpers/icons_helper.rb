module IconsHelper
  ICON = "<svg class=\"icon\"></svg>".freeze

  def icon
    ICON.html_safe
  end

  def separator
    sep = "&middot;"
    sep.html_safe
  end

  def list(items)
    safe_join(items.map { |i| content_tag(:li, i) })
  end

  def count_badge(n)
    "<b>#{n.to_i}</b>".html_safe
  end
end
