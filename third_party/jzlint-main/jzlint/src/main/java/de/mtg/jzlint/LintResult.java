package de.mtg.jzlint;

public class LintResult {

    private Status status;
    private String details;

    private LintResult() {
        // empty
    }

    private LintResult(Status status) {
        this.status = status;
    }

    private LintResult(Status status, String details) {
        this.status = status;
        this.details = details;
    }

    public static LintResult of(Status status) {
        return new LintResult(status);
    }

    public static LintResult of(Status status, String details) {
        return new LintResult(status, details);
    }

    public Status getStatus() {
        return status;
    }

    public String getDetails() {
        return details;
    }

}
