module DisplayHelper
  SEPARATOR = "<span>|</span>"

  def notice_for(user)
    t("notices.welcome_html", name: user.name).html_safe
  end

  def summary(text)
    sanitize(text, tags: %w[b i]).html_safe
  end

  def label(text)
    h(text).html_safe
  end

  def sep
    SEPARATOR.html_safe
  end

  def items(list)
    safe_join(list.map { |i| content_tag(:li, i) })
  end

  def icon
    markup = '<svg class="icon"></svg>'
    markup.html_safe
  end

  def link(user)
    link_to(user.name, user_path(user)).html_safe
  end

  def safe?(value)
    value.html_safe?
  end
end
