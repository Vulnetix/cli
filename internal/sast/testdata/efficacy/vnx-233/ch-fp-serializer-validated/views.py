from rest_framework.views import APIView


class Create(APIView):
    def post(self, request):
        s = OrderSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        Order.objects.create(**s.validated_data)
        return Response(status=201)
