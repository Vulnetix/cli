class ArchiveJob < ApplicationJob
  def perform_now_from(request)
    bucket = request.params[:bucket]
    cmd = format("aws s3 sync /data s3://%s", bucket)
~>    Open3.capture2(cmd)
~>    Open3.pipeline("ls /data", "gzip > /tmp/#{bucket}.gz")
  end
end
