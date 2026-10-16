<?php

~>$hashedPassword = crypt($plain, '$1$' . $salt . '$');
