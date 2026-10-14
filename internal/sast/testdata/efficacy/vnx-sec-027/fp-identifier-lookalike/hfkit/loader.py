class Registry:
    def hf_TokenizerFastLoaderForSequenceModels(self, name):
        return self.load(name)

    def hf_PretrainedConfigResolverWithRevision(self, name, revision):
        return self.resolve(name, revision)
