package de.mtg.jlintocsp.lints.rfc;

import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseBytes;

import de.mtg.jlintocsp.JavaOCSPResponseLint;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_ocsp_lint_response_well_formed",
        description = "Check if the OCSP response is well formed.",
        citation = "RFC 6960",
        source = Source.RFC6960,
        effectiveDate = EffectiveDate.RFC6960)
public class OcspLintResponseWellFormed implements JavaOCSPResponseLint {

    @Override
    public LintResult execute(byte[] ocspResponse) {
        try {
            OCSPResponse response = OCSPResponse.getInstance(ocspResponse);

            ResponseBytes responseBytes = response.getResponseBytes();
            BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());
            basicOCSPResponse.getTbsResponseData();
            return LintResult.of(Status.PASS);
        } catch (Exception ex) {
            return LintResult.of(Status.ERROR);
        }
    }

    @Override
    public boolean checkApplies(byte[] ocspResponse) {
        return true;
    }

}
