<?php

class Reports
{
    public function byOwner($collection, $owner)
    {
~>        return $collection->find(['$where' => "this.owner == '" . $owner . "'"]);
    }

    public function byLevel($collection, $level)
    {
~>        return $collection->find(['$where' => "this.level > $level"]);
    }
}
