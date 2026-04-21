package de.mtg.jzlint.lints.mozilla;

import java.math.BigInteger;
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
 Section 5.2 - Forbidden and Required Practices
 CAs MUST NOT issue certificates that have:
 - invalid public keys (e.g., RSA certificates with public exponent equal to 1);
 ********************************************************************/

@Lint(
        name = "e_mp_exponent_cannot_be_one",
        description = "CAs MUST NOT issue certificates that have invalid public keys (e.g., RSA certificates with public exponent equal to 1)",
        citation = "Mozilla Root Store Policy / Section 5.2",
        source = Source.MOZILLA_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.MozillaPolicy24Date)
public class MpExponentCannotBeOne implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        if (rsaPublicKey.getPublicExponent().compareTo(BigInteger.ONE) == 0) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyRSA(certificate);
    }

}
