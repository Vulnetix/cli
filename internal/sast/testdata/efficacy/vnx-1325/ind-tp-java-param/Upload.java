import javax.servlet.http.*;
public class Upload extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse resp) {
    int size = Integer.parseInt(request.getParameter("chunk"));
~>    byte[] data = new byte[size];
    process(data);
  }
}
