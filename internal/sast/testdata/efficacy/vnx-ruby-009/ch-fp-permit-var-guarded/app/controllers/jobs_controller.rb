class JobsController < ApplicationController
  KINDS = %w[rebuild reindex].freeze

  def run
    job_params = params.require(:job).permit(:kind, :target)
    kind = job_params[:kind]
    raise ActionController::BadRequest unless KINDS.include?(kind)

    Target.find(job_params[:target]).send(kind)
    redirect_to jobs_path
  end
end
