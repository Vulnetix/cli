package com.acme;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class RangeParserTest {
    @ParameterizedTest
    @CsvSource({"1-2,1,2,true,false,0,0,ok"})
    void parses(String in, int lo, int hi, boolean closedLo, boolean closedHi, int skip, int step,
                String expected) {
        assertEquals(expected, RangeParser.parse(in).toString());
    }
}
