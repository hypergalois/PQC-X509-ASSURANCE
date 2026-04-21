package de.mtg.jlint.lints.cabf_br;

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

/**
 * 7.2.2 CRL and CRL entry extensions
 * 1. reasonCode (OID 2.5.29.21)
 * The CRLReason indicated MUST NOT be unspecified (0)
 */

@Lint(
        name = "e_crl_entry_reason_code_unspecified",
        description = "Check if a CRL entry of a CRL has a reasonCode unspecified",
        citation = "BRs: 7.2.2 CRL and CRL entry extensions",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CRL_REASON_CODE_UPDATE)
public class CrlEntryReasonCodeUnspecified implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {

        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();

        if (revokedCertificates == null || revokedCertificates.isEmpty()) {
            return LintResult.of(Status.PASS);
        }

        for (X509CRLEntry crlEntry : revokedCertificates) {

            byte[] encoded = crlEntry.getExtensionValue(Extension.reasonCode.getId());

            CRLReason crlReason = CRLReason.getInstance(ASN1OctetString.getInstance(encoded).getOctets());
            if (crlReason.getValue().equals(BigInteger.ZERO)) {
                return LintResult.of(Status.ERROR);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509CRL crl) {
        return CRLUtils.atLeastOneCrlEntryHasExtension(crl, Extension.reasonCode.getId());
    }

}
