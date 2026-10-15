class UserCounter
  def next_user_id
    @last_user_id += 1
  end

  def visit(session)
    session[:views] += 1
    @line_no = @line_no.succ
  end
end
