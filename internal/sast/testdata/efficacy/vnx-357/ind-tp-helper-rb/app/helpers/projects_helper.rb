module ProjectsHelper
  def project_actions(project)
    safe_join([
      link_to(t('.edit'), edit_project_path(project), class: 'btn'),
~>      link_to(t('.delete'), project_path(project), method: :delete, class: 'btn btn-danger')
    ], ' ')
  end
end
