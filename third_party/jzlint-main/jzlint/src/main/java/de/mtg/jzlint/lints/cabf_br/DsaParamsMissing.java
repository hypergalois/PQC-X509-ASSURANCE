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
        name = "e_dsa_params_missing",
        description = "DSA: Certificates MUST include all domain parameters",
        citation = "BRs v1.7.0: 6.1.6",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate,
        ineffectiveDate = IneffectiveDate.CABFBRs_1_7_1_Date)
public class DsaParamsMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final DSAPublicKey dsaPublicKey = (DSAPublicKey) certificate.getPublicKey();
        final DSAParams dsaParams = dsaPublicKey.getParams();

        if (dsaParams == null) {
            return LintResult.of(Status.ERROR);
        }

        if (dsaParams.getP() == null) {
            return LintResult.of(Status.ERROR);
        }

        if (dsaParams.getQ() == null) {
            return LintResult.of(Status.ERROR);
        }

        if (dsaParams.getG() == null) {
            return LintResult.of(Status.ERROR);
        }

        final int pBitLength = dsaParams.getP().bitLength();
        final int qBitLength = dsaParams.getQ().bitLength();
        final int gBitLength = dsaParams.getG().bitLength();

        if (pBitLength == 0 || qBitLength == 0 || gBitLength == 0) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyDSA(certificate);
    }

}
