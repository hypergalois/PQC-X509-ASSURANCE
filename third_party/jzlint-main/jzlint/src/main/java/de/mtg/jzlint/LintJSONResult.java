package de.mtg.jzlint;

public class LintJSONResult {

    private final String name;
    private final String result;

    public LintJSONResult(String name, Status result) {
        this.name = name;
        this.result = getResultString(result);
    }

    public String getName() {
        return name;
    }

    public String getResult() {
        return result;
    }

    public static String getResultString(Status result) {
        if (result == Status.ERROR || result == Status.PASS || result == Status.FATAL || result == Status.WARN) {
            return result.name().toLowerCase();
        } else if (result == Status.NOTICE) {
            return "info";
        } else if (result == Status.NE) {
            return "ne";
        } else if (result == Status.NA) {
            return "na";
        } else {
            return result.name();
        }
    }

}
