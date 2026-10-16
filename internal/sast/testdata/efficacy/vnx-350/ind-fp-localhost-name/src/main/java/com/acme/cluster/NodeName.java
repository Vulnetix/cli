package com.acme.cluster;

import java.net.InetAddress;

public class NodeName {
    public static boolean isLeader(String leader) throws Exception {
        String me = InetAddress.getLocalHost().getHostName();
        return me.equals(leader);
    }
}
