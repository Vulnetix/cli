FEATURES = YAML.load_file(Rails.root.join("config", "features.yml"))
LOCALES = YAML.load(File.read(File.expand_path("../locales.yml", __dir__)))
SCHEMA = YAML.load(ERB.new(File.read("config/schema.yml")).result)
