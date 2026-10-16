import javax.servlet.http.*;
public class Chunk extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse resp) {
    int want = Integer.parseInt(request.getParameter("chunk"));
    int size = Math.min(want, 65536);
    byte[] data = new byte[size];
    ByteBuffer fixed = ByteBuffer.allocate(8192);
    process(data);
  }
}
