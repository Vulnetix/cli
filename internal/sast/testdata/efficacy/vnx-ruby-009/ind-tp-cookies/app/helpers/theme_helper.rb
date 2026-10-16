module ThemeHelper
  def render_theme
    style = cookies[:theme_style]
~>    Themes.send style
  end
end
