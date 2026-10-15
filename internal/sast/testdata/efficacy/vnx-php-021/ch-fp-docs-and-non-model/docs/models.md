# Models

Never write `protected $guarded = [];` in a model, and never call
`Model::unguard();` in a service provider. List the attributes in `$fillable`.
