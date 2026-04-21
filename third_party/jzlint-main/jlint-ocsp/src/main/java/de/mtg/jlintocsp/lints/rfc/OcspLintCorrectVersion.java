package de.mtg.jlintocsp.lints.rfc;

import java.math.BigInteger;

import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseBytes;

import de.mtg.jlintocsp.JavaOCSPResponseLint;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

//4.2.2.3.  Basic Response
//
//        The basic response type contains:
//
//        o  the version of the response syntax, which MUST be v1 (value is 0)
//        for this version of the basic response syntax;
@Lint(
        name = "e_ocsp_lint_correct_version",
        description = "Check if the version of the basic response is v1 (value is 0)",
        citation = "RFC 6960, Sec. 4.2.2.3",
        source = Source.RFC6960,
        effectiveDate = EffectiveDate.RFC6960)
public class OcspLintCorrectVersion implements JavaOCSPResponseLint {

    @Override
    public LintResult execute(byte[] ocspResponse) {
        OCSPResponse response = OCSPResponse.getInstance(ocspResponse);

        ResponseBytes responseBytes = response.getResponseBytes();
        BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());
        BigInteger version = basicOCSPResponse.getTbsResponseData().getVersion().getValue();

        if (version.equals(BigInteger.ZERO)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR, String.format("Wrong OCSP response version %s", version));

    }

    @Override
    public boolean checkApplies(byte[] ocspResponse) {
        return true;
    }

}
