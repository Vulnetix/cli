<?php
~>$policy = "Content-Security-Policy: script-src 'self' '@@sample:n[o]nc[e][-]c[2]Vj[c]mV[0]bm[9]uY[2]U@@=';";
header($policy);
?>
~><script nonce="c2VjcmV0bm9uY2U=">render();</script>
