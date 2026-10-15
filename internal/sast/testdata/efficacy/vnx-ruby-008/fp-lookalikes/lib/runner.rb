class Runner
  def pipeline(cmd)
    MyOpen3.capture2("echo #{cmd}")
    queue.pipeline("job #{params}")
    Sidekiq.redis { |r| r.pipelined { |p| p.set("k", "v") } }
  end
end
