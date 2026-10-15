def show
~>  if current_user.admin? || current_user.admin?
    render :show
  end
end
