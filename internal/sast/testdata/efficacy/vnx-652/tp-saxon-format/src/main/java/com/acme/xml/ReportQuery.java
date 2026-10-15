package com.acme.xml;

import @@sample:n[e]t[.][s]f[.][s]ax[o]n[.][s]9a[p]i[.][P]ro[c]es[s]or@@;
import @@sample:n[e]t[.][s]f[.][s]ax[o]n[.][s]9a[p]i[.][X]Qu[e]ry[C]om[p]il[e]r@@;
import @@sample:n[e]t[.][s]f[.][s]ax[o]n[.][s]9a[p]i[.][X]Qu[e]ry[E]xe[c]ut[a]bl[e]@@;

public class ReportQuery {
    private final Processor processor = new Processor(false);

    public XQueryExecutable compile(String region) throws Exception {
        XQueryCompiler compiler = processor.newXQueryCompiler();
~>        return compiler.compile(String.format("//sale[region='%s']", region));
    }
}
