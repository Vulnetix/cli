module CommentsHelper
  def render_comment(comment)
    html = "<p>#{comment.text}</p>"
~>    html.html_safe
  end

  def signature(user)
~>    raw(user.signature)
  end

  def preview(text)
    out = "<div>"
    out << text
~>    out.html_safe
  end
end
