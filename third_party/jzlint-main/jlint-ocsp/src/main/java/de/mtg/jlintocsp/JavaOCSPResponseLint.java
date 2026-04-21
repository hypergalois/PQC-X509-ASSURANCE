package de.mtg.jlintocsp;

import de.mtg.jzlint.LintResult;

public interface JavaOCSPResponseLint {

    LintResult execute(byte[] ocspResponse);

    boolean checkApplies(byte[] ocspResponse);

}
