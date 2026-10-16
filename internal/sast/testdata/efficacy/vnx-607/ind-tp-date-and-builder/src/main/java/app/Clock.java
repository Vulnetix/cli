package app;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.EnumSet;

public class Clock {
~>    public static final SimpleDateFormat STAMP = new SimpleDateFormat("yyyy-MM-dd");
~>    public static final Date EPOCH = new Date(0L);
~>    public static final StringBuilder LOG = new StringBuilder();
~>    public static final EnumSet<Mode> MODES = EnumSet.noneOf(Mode.class);
    public enum Mode { A, B }
}
