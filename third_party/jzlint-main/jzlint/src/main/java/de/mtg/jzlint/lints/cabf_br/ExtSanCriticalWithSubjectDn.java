package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/************************************************
 Further, if the only subject identity included in the certificate is an
 alternative name form (e.g., an electronic mail address), then the subject
 distinguished name MUST be empty (an empty sequence), and the subjectAltName
 extension MUST be present. If the subject field contains an empty sequence,
 then the issuing CA MUST include a subjectAltName extension that is marked as
 critical. When including the subjectAltName extension in a certificate that
 has a non-empty subject distinguished name, conforming CAs SHOULD mark the
 subjectAltName extension as non-critical.
 ************************************************/

@Lint(
        name = "w_ext_san_critical_with_subject_dn",
        description = "If the subject contains a distinguished name, subjectAlternateName SHOULD be non-critical",
        citation = "RFC 5280: 4.2.1.6",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtSanCriticalWithSubjectDn implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> rdns = Utils.getSubjectDNNameComponents(certificate);

        if (!rdns.isEmpty() && Utils.isExtensionCritical(certificate, Extension.subjectAlternativeName.getId())) {
            return LintResult.of(Status.WARN);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId());
    }

}
