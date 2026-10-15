package com.acme.http;

import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@;

public class Clients {
	static final OkHttpClient CLIENT;

	static
	{
~>		CLIENT = new OkHttpClient.Builder().build();
	}

	public static OkHttpClient get() {
		return new OkHttpClient();
	}
}
