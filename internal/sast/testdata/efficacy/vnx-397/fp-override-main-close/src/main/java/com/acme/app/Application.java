package com.acme.app;

import java.util.concurrent.Callable;
import org.springframework.web.servlet.HandlerInterceptor;

public class Application implements AutoCloseable, HandlerInterceptor {
    public static void main(String[] args) throws Exception {
        new Application().start();
    }

    @Override
    public void close() throws Exception {
        pool.shutdown();
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
            Object handler) throws Exception {
        return true;
    }

    static class Task implements Callable<String> {
        public String call() throws Exception {
            return "done";
        }
    }
}
