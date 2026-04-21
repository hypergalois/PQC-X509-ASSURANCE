package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.IneffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_dsa_shorter_than_2048_bits",
        description = "DSA modulus size must be at least 2048 bits",
        citation = "BRs v1.7.0: 6.1.5",
// Refer to BRs: 6.1.5, taking the statement "Before 31 Dec 2010" literally
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.ZERO,
        ineffectiveDate = IneffectiveDate.CABFBRs_1_7_1_Date)
public class DsaShorterThan2048Bits implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final DSAPublicKey dsaPublicKey = (DSAPublicKey) certificate.getPublicKey();
        final DSAParams dsaParams = dsaPublicKey.getParams();

        final int pBitLength = dsaParams.getP().bitLength();
        final int qBitLength = dsaParams.getQ().bitLength();

        if (pBitLength >= 2048 && qBitLength >= 244) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyDSA(certificate);
    }

}
