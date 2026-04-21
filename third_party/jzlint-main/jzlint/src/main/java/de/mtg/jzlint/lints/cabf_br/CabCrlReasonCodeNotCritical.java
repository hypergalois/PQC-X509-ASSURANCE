package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Set;
import java.util.function.Predicate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaCRLLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.CRLUtils;

@Lint(
        name = "e_cab_crl_reason_code_not_critical",
        description = "If present, CRL Reason Code extension MUST NOT be marked critical.",
        citation = "BRs: 7.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CabCrlReasonCodeNotCritical implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {

        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();

        if (revokedCertificates == null || revokedCertificates.isEmpty()) {
            return LintResult.of(Status.PASS);
        }

        for (X509CRLEntry crlEntry : revokedCertificates) {

            Predicate<String> oidEquals = oid -> oid.equals(Extension.reasonCode.getId());
            boolean found = crlEntry.getCriticalExtensionOIDs().stream().anyMatch(oidEquals);

            if (found) {
                return LintResult.of(Status.ERROR, "CRL Reason Code extension MUST NOT be marked as critical.");
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509CRL crl) {
        return CRLUtils.containsRevokedCertificates(crl);
    }

}

