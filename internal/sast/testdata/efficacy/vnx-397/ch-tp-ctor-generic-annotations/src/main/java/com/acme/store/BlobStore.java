package com.acme.store;

import java.util.Map;

public class BlobStore {
~>    public BlobStore(String uri, Map<String, String> opts) throws Exception {
        connect(uri, opts);
    }

    public <T> T read(Class<T> type,
                      @Nullable String key)
~>            throws java.lang.Exception {
        return codec.decode(type, fetch(key));
    }

    @Transactional
~>    protected void write(String key, byte[] data) throws IOException, Exception
    {
        put(key, data);
    }
}
