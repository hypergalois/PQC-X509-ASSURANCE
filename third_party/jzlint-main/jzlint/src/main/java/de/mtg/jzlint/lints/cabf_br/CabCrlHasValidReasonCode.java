package de.mtg.jzlint.lints.cabf_br;

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

@Lint(
        name = "e_cab_crl_has_valid_reason_code",
        description = "Only the following CRLReasons MAY be present: 1, 3, 4, 5, 9.",
        citation = "BRs: 7.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_8_7_Date)
public class CabCrlHasValidReasonCode implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {

        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();

        for (X509CRLEntry crlEntry : revokedCertificates) {

            byte[] encoded = crlEntry.getExtensionValue(Extension.reasonCode.getId());

            if (encoded != null) {
                CRLReason crlReason = CRLReason.getInstance(ASN1OctetString.getInstance(encoded).getOctets());
                BigInteger value = crlReason.getValue();
                if (value.equals(BigInteger.ZERO)) {
                    return LintResult.of(Status.ERROR,
                            "The reason code CRL entry extension SHOULD be absent instead of using the unspecified (0) reasonCode value.");
                } else if (!(value.equals(BigInteger.valueOf(1))
                        || value.equals(BigInteger.valueOf(3))
                        || value.equals(BigInteger.valueOf(4))
                        || value.equals(BigInteger.valueOf(5))
                        || value.equals(BigInteger.valueOf(9)))
                ) {
                    return LintResult.of(Status.ERROR, "Reason code not included in BR: 7.2.2");
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
