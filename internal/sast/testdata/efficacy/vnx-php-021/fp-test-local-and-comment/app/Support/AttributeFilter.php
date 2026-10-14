<?php

namespace App\Support;

class AttributeFilter
{
    // Never write protected $guarded = []; on a model.
    public function filter(array $attributes, array $rules)
    {
        $guarded = [];
        foreach ($rules as $key => $rule) {
            if ($rule === 'guarded') {
                $guarded[] = $key;
            }
        }
        $doc = 'Model::unguard() disables protection';
        return array_diff_key($attributes, array_flip($guarded));
    }
}
