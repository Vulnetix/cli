import graphene


class DeleteNote(graphene.Mutation):
    class Arguments:
        id = graphene.ID(required=True)

    ok = graphene.Boolean()

~>    def mutate(self, info, id):
        Note.objects.get(pk=id).delete()
        return DeleteNote(ok=True)
