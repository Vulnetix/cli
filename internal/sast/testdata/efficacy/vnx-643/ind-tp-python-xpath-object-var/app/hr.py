import lxml.etree
from django.http import JsonResponse

DOC = lxml.etree.parse("/srv/hr/employees.xml")


def employee(request):
    emplid = request.GET.get("id", "")
    query = "/Employees/Employee[@emplid='{}']/Name".format(emplid)
~>    finder = lxml.etree.XPath(query)
    names = [n.text for n in finder(DOC)]
    return JsonResponse({"names": names})
