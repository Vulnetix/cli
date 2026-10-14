package rpc

import (
	"bytes"
	"encoding/gob"

	"github.com/valyala/fasthttp"
)

type Call struct {
	Method string
	Args   []any
}

func Handle(ctx *fasthttp.RequestCtx) {
	body := bytes.NewReader(ctx.PostBody())
	var call Call
~>	if err := gob.NewDecoder(body).Decode(&call); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
	}
}
