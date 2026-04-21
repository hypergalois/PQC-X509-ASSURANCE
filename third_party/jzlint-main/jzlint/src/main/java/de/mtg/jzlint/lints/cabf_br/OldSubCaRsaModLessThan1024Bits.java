package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_old_sub_ca_rsa_mod_less_than_1024_bits",
        description = "In a validity period beginning on or before 31 Dec 2010 and ending on or before 31 Dec 2013, subordinate CA certificates using RSA public key algorithm MUST use a 1024 bit modulus",
        citation = "BRs: 6.1.5",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.ZERO)
public class OldSubCaRsaModLessThan1024Bits implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        if (rsaPublicKey.getModulus().bitLength() < 1024) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyRSA(certificate)
                && Utils.isSubCA(certificate)
                && !DateUtils.isIssuedOnOrAfter(certificate, EffectiveDate.NoRSA1024Date.getZonedDateTime())
                && DateUtils.expiresBefore(certificate, EffectiveDate.NoRSA1024Date.getZonedDateTime());
    }


}
