package xds

import (
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

func downstreamContext(certName string) *@@sample:t[l]sv[3][.]D[o]wn[s]tr[e]am[T]ls[C]on[t]ex[t]@@ {
	return &@@sample:t[l]sv[3][.]D[o]wn[s]tr[e]am[T]ls[C]on[t]ex[t]@@{
		CommonTlsContext: &@@sample:t[l]sv[3][.]C[o]mm[o]nT[l]sC[o]nt[e]xt@@{
			TlsParams: &tlsv3.TlsParameters{
~>				TlsMinimumProtocolVersion: @@sample:t[l]sv[3][.]T[l]sP[a]ra[m]et[e]rs[_]TL[S]v1[_]0@@,
				TlsMaximumProtocolVersion: @@sample:t[l]sv[3][.]T[l]sP[a]ra[m]et[e]rs[_]TL[S]v1[_]3@@,
			},
		},
	}
}

func strictParams() *tlsv3.TlsParameters {
	return &tlsv3.TlsParameters{
		TlsMinimumProtocolVersion: @@sample:t[l]sv[3][.]T[l]sP[a]ra[m]et[e]rs[_]TL[S]v1[_]2@@,
	}
}
