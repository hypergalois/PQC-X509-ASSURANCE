package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_dsa_improper_modulus_or_divisor_size",
        description = "Certificates MUST meet the following requirements for DSA algorithm type and key size: L=2048 and N=224,256 or L=3072 and N=256",
        citation = "BRs v1.7.0: 6.1.5",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.ZERO)
public class DsaImproperModulusOrDivisorSize implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final DSAPublicKey dsaPublicKey = (DSAPublicKey) certificate.getPublicKey();
        final DSAParams dsaParams = dsaPublicKey.getParams();

        final int pBitLength = dsaParams.getP().bitLength();
        final int qBitLength = dsaParams.getQ().bitLength();

        if ((pBitLength == 2048 && qBitLength == 224) || (pBitLength == 2048 && qBitLength == 256) || (pBitLength == 3072 && qBitLength == 256)) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyDSA(certificate);
    }

}
