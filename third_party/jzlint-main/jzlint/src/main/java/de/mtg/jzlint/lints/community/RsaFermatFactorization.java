package de.mtg.jzlint.lints.community;

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

@Lint(
        name = "e_rsa_fermat_factorization",
        description = "RSA key pairs that are too close to each other are susceptible to the Fermat Factorization Method (for more information please see https://en.wikipedia.org/wiki/Fermat%27s_factorization_method and https://fermatattack.secvuln.info/)",
        citation = "Pierre de Fermat",
        source = Source.COMMUNITY,
        effectiveDate = EffectiveDate.ZERO)
public class RsaFermatFactorization implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        BigInteger n = rsaPublicKey.getModulus();
        BigInteger sqrt = Utils.calculateSquareRoot(n);

        BigInteger a = sqrt.add(BigInteger.ONE);
        BigInteger b = a.pow(2).subtract(n);

        int rounds = 100;
        for (int i = 0; i < rounds; i++) {
            BigInteger bSqrt = Utils.calculateSquareRoot(b);
            if (bSqrt.pow(2).compareTo(b) == 0) {
                BigInteger p = a.subtract(bSqrt);
                BigInteger q = a.add(bSqrt);
                return LintResult.of(Status.ERROR, String.format("public modulus n = pq factored into p: %s; q: %s", p.toString(), q.toString()));
            }

            a = a.add(BigInteger.ONE);
            b = a.pow(2).subtract(n);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyRSA(certificate);
    }

}
