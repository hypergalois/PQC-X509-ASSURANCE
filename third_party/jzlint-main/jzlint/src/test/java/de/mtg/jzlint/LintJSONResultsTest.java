package de.mtg.jzlint;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class LintJSONResultsTest {

    @Test
    void test() throws JsonProcessingException {

        Map<String, Map<String, String>> map = new HashMap<>();
        Map<String, String> valueMap = new HashMap<>();
        map.put("key", valueMap);
        map.put("key2", valueMap);
        valueMap.put("result", "na");

        ObjectMapper mapper = new ObjectMapper();
        String jacksonPrettyResult = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(map);
        String jacksonResult = mapper.writeValueAsString(map);

        LintJSONResult lintJSONResult1 = new LintJSONResult("key2", Status.NA);
        LintJSONResult lintJSONResult2 = new LintJSONResult("key", Status.NA);
        List<LintJSONResult> lintJSONResultsList = new ArrayList<>();
        lintJSONResultsList.add(lintJSONResult1);
        lintJSONResultsList.add(lintJSONResult2);
        LintJSONResults lintJSONResults = new LintJSONResults(lintJSONResultsList);

        String serializationResult = mapper.writeValueAsString(lintJSONResults.getResult());

        assertNotNull(serializationResult);

        TypeReference<Map<String, Map<String, String>>> typeReference = new TypeReference<Map<String, Map<String, String>>>() {
        };
        Map<String, Map<String, String>> readMap = mapper.readValue(serializationResult, typeReference);
        assertEquals(2, readMap.size());

        assertEquals(readMap, lintJSONResults.getResult());
        assertEquals(jacksonPrettyResult, lintJSONResults.getResultPrettyString());
        assertEquals(jacksonResult, lintJSONResults.getResultString());

    }

}
