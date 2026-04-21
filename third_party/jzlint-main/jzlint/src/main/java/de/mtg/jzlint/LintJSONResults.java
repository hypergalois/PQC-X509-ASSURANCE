package de.mtg.jzlint;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LintJSONResults {

    public static final String RESULT = "result";

    Map<String, Map<String, String>> result = new HashMap<>();

    public LintJSONResults(List<LintJSONResult> lintJSONResults) {
        for (LintJSONResult lintJSONResult : lintJSONResults) {
            Map<String, String> valueMap = new HashMap<>();
            valueMap.put(RESULT, lintJSONResult.getResult());
            this.result.put(lintJSONResult.getName(), valueMap);
        }
    }

    public Map<String, Map<String, String>> getResult() {
        return this.result;
    }

    public String getResultString() {

        if (this.result.isEmpty()) {
            return "{}";
        }

        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("{");
        for (String key : this.result.keySet()) {
            stringBuilder.append(printOneResult(key, this.result.get(key)));
            stringBuilder.append(",");
        }
        stringBuilder.append("}");
        stringBuilder.deleteCharAt(stringBuilder.toString().lastIndexOf(","));
        return stringBuilder.toString();
    }

    public String getResultPrettyString() {

        if (this.result.isEmpty()) {
            return "{}";
        }

        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("{");
        stringBuilder.append(System.lineSeparator());
        for (String key : this.result.keySet()) {
            stringBuilder.append(prettyPrintOneResult(key, this.result.get(key)));
            stringBuilder.append(",");
            stringBuilder.append(System.lineSeparator());
        }
        stringBuilder.append("}");
        stringBuilder.deleteCharAt(stringBuilder.toString().lastIndexOf(","));
        return stringBuilder.toString();
    }

    private String printOneResult(String key, Map<String, String> value) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("\"");
        stringBuilder.append(key);
        stringBuilder.append("\"");
        stringBuilder.append(":{");
        stringBuilder.append("\"");
        String valueKey = value.keySet().iterator().next();
        stringBuilder.append(valueKey);
        stringBuilder.append("\":\"");
        stringBuilder.append(value.get(valueKey));
        stringBuilder.append("\"");
        stringBuilder.append("}");
        return stringBuilder.toString();
    }

    private static String prettyPrintOneResult(String key, Map<String, String> value) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("  ");
        stringBuilder.append("\"");
        stringBuilder.append(key);
        stringBuilder.append("\"");
        stringBuilder.append(" : {");
        stringBuilder.append(System.lineSeparator());
        stringBuilder.append("    ");
        stringBuilder.append("\"");
        String valueKey = value.keySet().iterator().next();
        stringBuilder.append(valueKey);
        stringBuilder.append("\" : \"");
        stringBuilder.append(value.get(valueKey));
        stringBuilder.append("\"");
        stringBuilder.append(System.lineSeparator());
        stringBuilder.append("  }");
        return stringBuilder.toString();
    }

}
