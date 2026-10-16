from django.conf import settings
from django.urls import path
from graphene_django.views import GraphQLView

urlpatterns = [
    path("graphql", GraphQLView.as_view(graphiql=settings.DEBUG)),
]
if settings.DEBUG:
    urlpatterns += [path("explore", GraphQLView.as_view(graphiql=True))]
