package com.lib;

import net.sf.saxon.s9api.*;

public class Report {
    XdmValue run(Processor proc, String region) throws SaxonApiException {
        XQueryCompiler compiler = proc.newXQueryCompiler();
~>        XQueryExecutable exe = compiler.compile("sum(//sale[region='%s']/amount)".formatted(region));
        return exe.load().evaluate();
    }
}
