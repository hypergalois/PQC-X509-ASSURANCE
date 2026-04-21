package de.mtg.jzlint;

import java.security.cert.X509Certificate;

public interface JavaLint {

    LintResult execute(X509Certificate certificate);

    boolean checkApplies(X509Certificate certificate);
}


