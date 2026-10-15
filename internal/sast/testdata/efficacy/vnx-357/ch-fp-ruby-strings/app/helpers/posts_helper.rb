module PostsHelper
  def delete_post_link(post)
    link_to "Delete", post, method: :delete, data: { confirm: t("posts.confirm_delete") }
  end

  def edit_link(post)
    link_to "Edit", edit_post_path(post)
  end
end
