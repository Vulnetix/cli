<?php
extract($_POST,
    EXTR_PREFIX_ALL, 'form');
extract($row);
extract(compact('title', 'body'));
extract($this->data);
