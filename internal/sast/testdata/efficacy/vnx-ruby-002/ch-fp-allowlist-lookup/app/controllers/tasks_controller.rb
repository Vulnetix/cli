class TasksController < ApplicationController
  TASKS = { "reindex" => "bin/rails search:reindex", "warm" => "bin/rails cache:warm" }.freeze

  def run
    command = TASKS.fetch(params[:task])
    system(command)
    count = params[:count].to_i
    system("bin/rails jobs:work COUNT=#{count}")
    head :ok
  end
end
