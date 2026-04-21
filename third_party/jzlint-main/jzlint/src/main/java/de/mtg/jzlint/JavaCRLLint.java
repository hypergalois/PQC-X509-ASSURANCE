package de.mtg.jzlint;

import java.security.cert.X509CRL;

public interface JavaCRLLint {

    LintResult execute(X509CRL crl);

    boolean checkApplies(X509CRL crl);

}
