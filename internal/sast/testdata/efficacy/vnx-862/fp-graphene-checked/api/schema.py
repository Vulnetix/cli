import graphene
from graphql import GraphQLError

from .models import Note, db


class DeleteNote(graphene.Mutation):
    ok = graphene.Boolean()

    class Arguments:
        id = graphene.Int()

    def mutate(self, info, id):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("login required")
        deleted = Note.query.filter_by(id=id, owner_id=user.id).delete()
        db.session.commit()
        return DeleteNote(ok=bool(deleted))
