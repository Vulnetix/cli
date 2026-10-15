module ProfilesHelper
  def bio_card(profile)
~>    content_tag(:div, profile.bio.html_safe, class: "bio")
  end

  def greeting(user)
~>    "<span class=\"hi\">Welcome back, #{user.display_name}</span>".html_safe
  end
end
