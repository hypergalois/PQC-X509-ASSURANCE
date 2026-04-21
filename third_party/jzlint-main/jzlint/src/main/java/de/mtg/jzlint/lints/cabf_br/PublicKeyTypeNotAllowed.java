package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_public_key_type_not_allowed",
        description = "Certificates MUST have RSA, DSA, or ECDSA public key type",
        citation = "BRs: 6.1.5",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class PublicKeyTypeNotAllowed implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isPublicKeyDSA(certificate) || Utils.isPublicKeyRSA(certificate) || Utils.isPublicKeyECC(certificate)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }


}
