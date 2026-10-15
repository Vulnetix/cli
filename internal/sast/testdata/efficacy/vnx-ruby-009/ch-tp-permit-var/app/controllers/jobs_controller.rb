class JobsController < ApplicationController
  def run
    job_params = params.require(:job).permit(:kind, :target)
    kind = job_params[:kind]
    target = Target.find(job_params[:target])

~>    target.send kind
    redirect_to jobs_path
  end
end
