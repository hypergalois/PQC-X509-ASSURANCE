package de.mtg.jzlint.lints.mozilla;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/********************************************************************
 Section 5.1 - Algorithms
 RSA keys whose modulus size in bits is divisible by 8, and is at least 2048.
 ********************************************************************/

@Lint(
        name = "e_mp_modulus_must_be_divisible_by_8",
        description = "RSA keys must have a modulus size divisible by 8",
        citation = "Mozilla Root Store Policy / Section 5.1",
        source = Source.MOZILLA_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.MozillaPolicy24Date)
public class MpModulusMustBeDivisibleBy8 implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        if (rsaPublicKey.getModulus().bitLength() % 8 != 0) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyRSA(certificate);
    }

}
