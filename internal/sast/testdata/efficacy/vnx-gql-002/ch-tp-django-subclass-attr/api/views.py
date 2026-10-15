from graphene_django.views import GraphQLView


class BatchedGraphQLView(GraphQLView):
~>    batch = True
    graphiql = False
