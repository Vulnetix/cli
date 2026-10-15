import Network

func makeParameters() -> NWParameters {
    let tls = NWProtocolTLS.Options()
~>    sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, complete in
        complete(true)
    }, .main)
    return NWParameters(tls: tls)
}
