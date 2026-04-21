package de.mtg.jzlint.lints.rfc;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Set;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaCRLLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.CRLUtils;

/*
***********************************************
RFC 5280: 5.3.1

	CRL issuers are strongly
	  encouraged to include meaningful reason codes in CRL entries;
	  however, the reason code CRL entry extension SHOULD be absent instead
	  of using the unspecified (0) reasonCode value.

***********************************************
*/

@Lint(
        name = "e_crl_has_valid_reason_code",
        description = "If a CRL entry has a reason code, it MUST be in RFC5280 section 5.3.1 and SHOULD be absent instead of using unspecified (0)",
        citation = "RFC 5280: 5.3.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class CrlHasValidReasonCode implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {

        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();

        for (X509CRLEntry crlEntry : revokedCertificates) {

            byte[] encoded = crlEntry.getExtensionValue(Extension.reasonCode.getId());

            if (encoded != null) {
                CRLReason crlReason = CRLReason.getInstance(ASN1OctetString.getInstance(encoded).getOctets());
                BigInteger value = crlReason.getValue();
                if (value.equals(BigInteger.ZERO)) {
                    return LintResult.of(Status.WARN,
                            "The reason code CRL entry extension SHOULD be absent instead of using the unspecified (0) reasonCode value.");
                } else if (value.equals(BigInteger.valueOf(7)) || value.compareTo(BigInteger.valueOf(10)) == 1) {
                    return LintResult.of(Status.ERROR, String.format("Reason code, %s, not included in RFC 5280 section 5.3.1", value));
                }
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509CRL crl) {
        return CRLUtils.containsRevokedCertificates(crl);
    }

}

