package de.mtg.jzlint.lints.cabf_br;

import java.math.BigInteger;
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
        name = "e_dsa_correct_order_in_subgroup",
        description = "DSA: Public key value has the unique correct representation in the field, and that the key has the correct order in the subgroup",
        citation = "BRs v1.7.0: 6.1.6",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate,
        ineffectiveDate = IneffectiveDate.CABFBRs_1_7_1_Date)
public class DsaCorrectOrderInSubgroup implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {


        final DSAPublicKey dsaPublicKey = (DSAPublicKey) certificate.getPublicKey();
        final DSAParams dsaParams = dsaPublicKey.getParams();

        final BigInteger p = dsaParams.getP();
        final BigInteger q = dsaParams.getQ();
        final BigInteger y = dsaPublicKey.getY();

        if (y.modPow(q, p).compareTo(BigInteger.ONE) == 0) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyDSA(certificate);
    }

}
