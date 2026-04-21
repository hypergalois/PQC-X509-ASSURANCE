package de.mtg.jlintocsp.lints.rfc;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;

import de.mtg.jlintocsp.JavaOCSPResponseLint;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_ocsp_lint_correct_response_status",
        description = "Check if the OCSPResponseStatus field contains only one of the allowed values.",
        citation = "RFC 6960, Sec. 4.2.1",
        source = Source.RFC6960,
        effectiveDate = EffectiveDate.RFC6960)
public class OcspLintCorrectResponseStatus implements JavaOCSPResponseLint {

    private static final List<Integer> ALLOWED_OCSP_RESPONSE_STATUS_VALUES = Arrays.asList(0, 1, 2, 3, 5, 6);

    @Override
    public LintResult execute(byte[] ocspResponse) {
        OCSPResponse response = OCSPResponse.getInstance(ocspResponse);
        OCSPResponseStatus responseStatus = response.getResponseStatus();

        if (Utils.isValueIn(responseStatus.getIntValue(), ALLOWED_OCSP_RESPONSE_STATUS_VALUES)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);

    }

    @Override
    public boolean checkApplies(byte[] ocspResponse) {
        return true;
    }

}
