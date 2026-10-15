package com.acme.sec;

public class Filter extends BaseFilter {
    @Override
    protected void doFilterInternal(
            final Request request,
            @Qualifier("primary") Response response,
            @Qualifier("chain") Chain chain,
            @Qualifier("ctx") Context context)
            throws Exception {
        chain.next(request, response);
    }
}
