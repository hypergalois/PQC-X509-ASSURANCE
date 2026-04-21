package de.mtg.jzlint.lints.apple;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.util.encoders.Hex;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;
import de.mtg.jzlint.utils.Utils;

// Execute checks if the provided certificate has embedded SCTs from
// a sufficient number of unique CT logs to meet Apple's CT log policy[0],
// effective Oct 15th, 2018.
//
// The number of required SCTs from different logs is calculated based on the
// Certificate's lifetime. If the number of required SCTs are not embedded in
// the certificate a Notice level lint.LintResult is returned.
//
// | Certificate lifetime | # of SCTs from separate logs |
// -------------------------------------------------------
// | Less than 15 months  | 2                            |
// | 15 to 27 months      | 3                            |
// | 27 to 39 months      | 4                            |
// | More than 39 months  | 5                            |
// -------------------------------------------------------
//
// Important note 1: We can't know whether additional SCTs were presented
// alongside the certificate via OCSP stapling. This linter assumes only
// embedded SCTs are used and ignores the portion of the Apple policy related to
// SCTs delivered via OCSP. This is one limitation that restricts the linter's
// findings to Notice level. See more background discussion in Issue 226[1].
//
// Important note 2: The linter doesn't maintain a list of Apple's trusted
// logs. The SCTs embedded in the certificate may not be from log's Apple
// actually trusts. Similarly the embedded SCT signatures are not validated
// in any way.
//
// [0]: https://support.apple.com/en-us/HT205280
// [1]: https://github.com/zmap/zlint/issues/226
@Lint(
        name = "w_ct_sct_policy_count_unsatisfied",
        description = "Check if certificate has enough embedded SCTs to meet Apple CT Policy",
        citation = "https://support.apple.com/en-us/HT205280",
        source = Source.APPLE_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.AppleCTPolicyDate)
public class CtSctPolicyCountUnsatisfied implements JavaLint {

    private static final String POISON_EXTENSION_OID = "1.3.6.1.4.1.11129.2.4.3";
    private static final String SCT_EXTENSION_OID = "1.3.6.1.4.1.11129.2.4.2";

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] sctValue = certificate.getExtensionValue(SCT_EXTENSION_OID);

        if (sctValue == null) {
            return LintResult.of(Status.NOTICE);
        }

        int numberOfDistinctSCTs = numberOfDistinctSCTs(sctValue);

        if (numberOfRequiredSCTs(certificate) <= numberOfDistinctSCTs) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.NOTICE);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && !Utils.hasExtension(certificate, POISON_EXTENSION_OID);
    }


    private static int numberOfDistinctSCTs(byte[] extensionValue) {
        // see also https://letsencrypt.org/2018/04/04/sct-encoding.html
        byte[] octets = ASN1OctetString.getInstance(extensionValue).getOctets();

        ASN1OctetString innerOctetString = ASN1OctetString.getInstance(octets);
        byte[] sctInnerValue = innerOctetString.getOctets();

        byte[] lengthArray = new byte[2];
        byte[] content = new byte[sctInnerValue.length - 2];
        System.arraycopy(sctInnerValue, 0, lengthArray, 0, 2);
        System.arraycopy(sctInnerValue, 2, content, 0, sctInnerValue.length - 2);
        int sctLength = new BigInteger(1, lengthArray).intValue();

        int byteCounter = 0;

        Map<String, String> logIDs = new HashMap<>();

        while (byteCounter < sctLength) {
            byte[] oneSctLengthArray = new byte[2];
            byte[] logID = new byte[32];
            System.arraycopy(content, byteCounter, oneSctLengthArray, 0, 2);
            System.arraycopy(content, byteCounter + 3, logID, 0, 32);
            int oneSctLength = new BigInteger(1, oneSctLengthArray).intValue();
            byteCounter = byteCounter + oneSctLength + 2;
            logIDs.put(new String(Hex.encode(logID)), new String(Hex.encode(logID)));
        }

        return logIDs.size();
    }

    private static int numberOfRequiredSCTs(X509Certificate certificate) {

        int validPeriodInMonths = DateUtils.getValidityInMonths(certificate);

        if (validPeriodInMonths < 15) {
            return 2;
        }

        if (validPeriodInMonths >= 15 && validPeriodInMonths <= 27) {
            return 3;
        }

        if (validPeriodInMonths >= 28 && validPeriodInMonths <= 39) {
            return 4;
        }

        return 5;
    }

}
