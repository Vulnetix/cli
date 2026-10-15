package com.acme;

import java.io.InputStream;
import java.util.Properties;

public class Config {
	static final Properties PROPS = new Properties();

	static{
		try (InputStream in = Config.class.getResourceAsStream("/app.properties")) {
			PROPS.load(in);
~>		} catch (Exception ignored) {
			// ignore, defaults are fine
		}
	}
}
