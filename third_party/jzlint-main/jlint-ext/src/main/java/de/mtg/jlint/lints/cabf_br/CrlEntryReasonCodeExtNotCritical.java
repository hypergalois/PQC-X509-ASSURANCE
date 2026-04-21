package de.mtg.jlint.lints.cabf_br;

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

/**
 * 7.2.2 CRL and CRL entry extensions
 * 1. reasonCode (OID 2.5.29.21)
 * If present, this extension MUST NOT be marked critical.
 */

@Lint(
        name = "e_crl_entry_reason_code_ext_not_critical",
        description = "Check if a CRL entry of a CRL contains a critical reasonCode extension",
        citation = "BRs: 7.2.2 CRL and CRL entry extensions",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CRL_REASON_CODE_UPDATE)
public class CrlEntryReasonCodeExtNotCritical implements JavaCRLLint {

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
