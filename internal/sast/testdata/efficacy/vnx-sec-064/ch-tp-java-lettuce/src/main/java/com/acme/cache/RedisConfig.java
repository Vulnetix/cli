package com.acme.cache;

import io.lettuce.core.RedisClient;

public class RedisConfig {
~>    RedisClient client = RedisClient.create("redis://default:@@sample:[A-Za-z0-9]{20}@@@@@sample:r[e]di[s][-]1[5]43[2][.]c[1][.]e[u][-]w[e]st[-]1[-][1][.]e[c]2[.][c]lo[u]d[.][r]ed[i]sl[a]bs[.]co[m]@@:15432");
}
