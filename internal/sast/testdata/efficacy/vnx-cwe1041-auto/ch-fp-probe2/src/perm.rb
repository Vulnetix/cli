def show
  if current_user.admin? || current_user.owner?
    render :show
  end
  x = a == b && b == a
end
