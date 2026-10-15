import graphene

from .models import AuditLog, Note, db


class DeleteNote(graphene.Mutation):
    ok = graphene.Boolean()

    class Arguments:
        id = graphene.Int()

~>    def mutate(self, info, id):
        deleted = Note.query.filter_by(id=id).delete()
        db.session.commit()
        return DeleteNote(ok=bool(deleted))


class Query(graphene.ObjectType):
    purge_logs = graphene.Boolean()

~>    def resolve_purge_logs(self, info):
        AuditLog.query.delete()
        db.session.commit()
        return True

    def resolve_count(self, info):
        return Note.query.count()
