package main

import tfe "github.com/hashicorp/go-tfe"

var cfg = &tfe.Config{
~>	Token: "@@sample:[A-Za-z0-9]{14}@@.atlasv1.@@sample:[A-Za-z0-9]{64}@@",
}
