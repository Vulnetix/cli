FEATURES = YAML.load_file(Rails.root.join("config", "features.yml"))
path = File.join(__dir__, "limits.yml")
LIMITS = YAML.load(File.read(path))
DEFAULTS = YAML.unsafe_load(ERB.new(File.read("config/defaults.yml")).result)
