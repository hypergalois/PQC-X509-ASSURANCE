package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 BRs: 7.1.4.2.1
 Subject Alternative Name Extension
 Certificate Field: extensions:subjectAltName
 Required/Optional: Required
 ************************************************/
@Lint(
        name = "e_ext_san_missing",
        description = "Subscriber certificates MUST contain the Subject Alternate Name extension",
        citation = "BRs: 7.1.4.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class ExtSanMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId())) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isCA(certificate);
    }

}
