class WorkflowsController < ApplicationController
  def create
~>    definition = YAML.unsafe_load(
      Base64.decode64(params[:definition])
    )
~>    docs = YAML.load_stream request.body.read
    Workflow.create!(definition: definition, docs: docs)
  end
end
