package de.mtg.jzlint.lints.cabf_br;

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

/**************************************************************************************************
 6.1.6. Public Key Parameters Generation and Quality Checking
 RSA: The CA SHALL confirm that the value of the public exponent is an odd number equal to 3 or more.
 Additionally, the public exponent SHOULD be in the range between 2^16+1 and 2^156-1.
 The modulus SHOULD also have the following characteristics: an odd number, not the power of a prime,
 and have no factors smaller than 752. [Citation: Section 5.3.3, NIST SP 800-89].
 **************************************************************************************************/

@Lint(
        name = "w_rsa_mod_factors_smaller_than_752",
        description = "RSA: Modulus SHOULD also have the following characteristics: no factors smaller than 752",
        citation = "BRs: 6.1.6",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABV113Date)
public class RsaModFactorsSmallerThan752 implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final BigInteger product = new BigInteger("1451887755777639901511587432083070202422614380984889313550570919659315177065956574359078912654149167643992684236991305777574330831666511589145701059710742276692757882915756220901998212975756543223550490431013061082131040808010565293748926901442915057819663730454818359472391642885328171302299245556663073719855");

        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        if (rsaPublicKey.getModulus().gcd(product).compareTo(BigInteger.ONE) != 0) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyRSA(certificate);
    }


}
