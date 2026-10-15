package com.acme.workflow;

import java.io.Serializable;
import com.acme.workflow.model.Process;
import com.acme.workflow.model.Connection;

public class Step implements Serializable {
    private Process owner;
    private Connection edge;
    private String label;
}
