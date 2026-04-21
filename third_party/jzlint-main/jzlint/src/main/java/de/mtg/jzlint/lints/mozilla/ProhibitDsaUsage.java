package de.mtg.jzlint.lints.mozilla;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
 Subsection 5.1 Algorithms
 Root certificates in our root program, and any certificate which chains up to them, MUST use only algorithms and key sizes from the following set:
 - RSA keys whose modulus size in bits is divisible by 8, and is at least 2048.
 - ECDSA keys using one of the following curves:
 + P-256
 + P-384
 ************************************************/

@Lint(
        name = "e_prohibit_dsa_usage",
        description = "DSA is not an explicitly allowed signature algorithm, therefore it is forbidden.",
        citation = "Mozilla Root Store Policy / Section 5.1",
        source = Source.MOZILLA_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.MozillaPolicy241Date)
public class ProhibitDsaUsage implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isPublicKeyDSA(certificate)) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}
