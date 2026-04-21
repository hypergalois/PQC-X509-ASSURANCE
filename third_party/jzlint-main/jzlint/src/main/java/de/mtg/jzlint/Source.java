package de.mtg.jzlint;

public enum Source {

    RFC2459("RFC"),
    RFC3279("RFC"),
    RFC5280("RFC"),
    RFC5480("RFC"),
    RFC5891("RFC"),
    RFC6960("RFC"),
    RFC8813("RFC"),
    APPLE_ROOT_STORE_POLICY("APPLE"),
    MOZILLA_ROOT_STORE_POLICY("MOZILLA"),
    COMMUNITY("COMMUNITY"),
    CABF_EV_GUIDELINES("CABF_EV"),
    CABF_BASELINE_REQUIREMENTS("CABF_BR"),
    ETSI_ESI("ETSI_ESI"),
    CABF_SMIME_BASELINE_REQUIREMENTS("CABF_SMIME"),
    CABF_CODE_SIGNING_BASELINE_REQUIREMENTS("CABF_CS"),
    PQC("PQC"),
    SM_PKI("SM_PKI");

    private final String sourceName;

    Source(String sourceName) {
        this.sourceName = sourceName;
    }

    public String getSourceName() {
        return sourceName;
    }

}
