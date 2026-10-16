package com.acme.entity;

import java.io.Serializable;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class Integration implements Serializable {
    @Id
    private Long id;

    @Column(name = "api_key", nullable = false)
~>    private String apiKey;

    @Column(name = "client_secret")
~>    private String clientSecret;

~>    private byte[] privateKey;

    private String displayName;
}
