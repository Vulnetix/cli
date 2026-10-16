module IconsHelper
  def check_icon
    '<i class="bi bi-check"></i>'.html_safe
  end

  def clean(text)
    sanitize(text, tags: %w[b i]).html_safe
  end

  def welcome(user)
    t("notices.welcome_html", name: user.name).html_safe
  end

  def messages_path_json
    "/users/#{current_user.id}/messages.json".inspect.html_safe
  end

  def safe?(value)
    value.html_safe?
  end
end
