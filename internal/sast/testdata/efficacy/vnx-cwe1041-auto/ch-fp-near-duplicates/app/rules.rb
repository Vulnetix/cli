class Rules
  def level(user)
    if user.admin?
      3
    elsif user.admin_of?(team)
      2
    elsif user.member?
      1
    end
  end

  def check
    authorize! :read, @post
    authorize! :update, @post
    ensure_owner(@post.author)
    ensure_owner(@post.editor)
    puts "user.admin? && user.admin?"
  end
end
