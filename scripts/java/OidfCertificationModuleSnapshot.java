// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.openid.conformance.info.Plan;
import net.openid.conformance.variant.VariantSelection;
import net.openid.conformance.variant.VariantService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves the certification module inventory through the suite's own
 * VariantService. This intentionally uses the same default and applicability
 * logic as POST /api/plan instead of approximating plan membership from source
 * file names.
 */
public final class OidfCertificationModuleSnapshot {
    private static final String EXPRESSION_FIELD = "expression";
    private static final String CERTIFICATION_RUNS_FIELD = "certification_runs";
    private static final String ENGINEERING_RUNS_FIELD = "engineering_runs";

    private OidfCertificationModuleSnapshot() {}

    public static void main(String[] arguments) throws IOException {
        if (arguments.length != 2) {
            throw new IllegalArgumentException("expected manifest and output paths");
        }

        Path manifestPath = Path.of(arguments[0]).toAbsolutePath().normalize();
        Path outputPath = Path.of(arguments[1]).toAbsolutePath().normalize();
        JsonObject manifest = parseObject(manifestPath);
        VariantService variantService = new VariantService(holder -> true);
        JsonObject snapshot = buildSnapshot(manifest, variantService);

        Path outputParent = outputPath.getParent();
        if (outputParent == null) {
            throw new IllegalArgumentException("output path must have a parent directory");
        }
        Files.createDirectories(outputParent);
        Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .serializeNulls()
            .create();
        Files.writeString(outputPath, gson.toJson(snapshot) + System.lineSeparator(), StandardCharsets.UTF_8);
    }

    private static JsonObject parseObject(Path path) throws IOException {
        JsonElement parsed = JsonParser.parseString(Files.readString(path, StandardCharsets.UTF_8));
        if (!parsed.isJsonObject()) {
            throw new IllegalArgumentException("certification manifest must be a JSON object");
        }
        return parsed.getAsJsonObject();
    }

    private static JsonObject buildSnapshot(JsonObject manifest, VariantService variantService) {
        JsonObject suiteTarget = requiredObject(manifest, "suite_target");
        JsonArray plans = requiredArray(manifest, "plans");
        JsonObject snapshot = new JsonObject();
        snapshot.addProperty("schema_version", 1);
        snapshot.addProperty(
            "source_copyright",
            "Copyright (c) 2019-2020 OpenID Foundation and other upstream contributors"
        );
        snapshot.addProperty("source_license", "MIT");
        snapshot.addProperty(
            "curation_copyright",
            "Copyright © 2026 ReallyMe Technologies Limited. All rights reserved"
        );
        snapshot.addProperty("curation_license", "MIT OR Apache-2.0");
        snapshot.addProperty("suite_ref", requiredString(suiteTarget, "pinned_ref"));
        snapshot.addProperty("suite_commit", requiredString(suiteTarget, "commit"));
        snapshot.addProperty("inventory_scope", optionalString(manifest, "scope", "certification"));
        snapshot.addProperty(
            "inventory_authority",
            "OpenID conformance-suite VariantService using POST /api/plan-equivalent default and applicability resolution"
        );

        JsonArray resolvedPlans = new JsonArray();
        int configurationCount = 0;
        int moduleExecutionCount = 0;
        for (JsonElement planElement : plans) {
            JsonObject plan = requireObjectElement(planElement, "plan");
            String planId = requiredString(plan, "plan_id");
            VariantService.TestPlanHolder holder = variantService.getTestPlan(planId);
            if (holder == null) {
                throw new IllegalArgumentException("certification plan is unavailable in the pinned suite");
            }

            JsonObject resolvedPlan = new JsonObject();
            resolvedPlan.addProperty("plan_id", planId);
            resolvedPlan.addProperty(
                "evidence_class",
                optionalString(plan, "evidence_class", "certification")
            );
            JsonArray configurations = new JsonArray();
            for (JsonElement runElement : requiredRunArray(plan)) {
                JsonObject run = requireObjectElement(runElement, "certification run");
                JsonObject resolved = resolveConfiguration(holder, run);
                moduleExecutionCount = Math.addExact(
                    moduleExecutionCount,
                    requiredInt(resolved, "module_count")
                );
                configurationCount = Math.addExact(configurationCount, 1);
                configurations.add(resolved);
            }
            resolvedPlan.add("configurations", configurations);
            resolvedPlans.add(resolvedPlan);
        }
        snapshot.addProperty("plan_configuration_count", configurationCount);
        snapshot.addProperty("module_execution_count", moduleExecutionCount);
        snapshot.add("plans", resolvedPlans);
        return snapshot;
    }

    private static JsonObject resolveConfiguration(
        VariantService.TestPlanHolder holder,
        JsonObject run
    ) {
        Map<String, String> selected = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> entry : run.entrySet()) {
            if (EXPRESSION_FIELD.equals(entry.getKey())) {
                continue;
            }
            JsonElement value = entry.getValue();
            if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException("certification run variants must be strings");
            }
            selected.put(entry.getKey(), value.getAsString());
        }

        VariantSelection selectedVariants = new VariantSelection(selected);
        Map<String, String> resolved = new LinkedHashMap<>(selected);
        resolved.putAll(holder.getUnsetDefaults(selectedVariants));
        VariantSelection resolvedVariants = new VariantSelection(resolved);
        List<Plan.Module> modules = holder.getTestModulesForVariant(resolvedVariants);
        if (modules.isEmpty()) {
            throw new IllegalArgumentException("certification configuration resolves to no modules");
        }

        Gson gson = new Gson();
        JsonObject configuration = new JsonObject();
        configuration.addProperty("expression", requiredString(run, EXPRESSION_FIELD));
        configuration.add("selected_variants", gson.toJsonTree(selected));
        configuration.add("resolved_variants", gson.toJsonTree(resolved));
        configuration.add(
            "suite_profile_labels",
            gson.toJsonTree(holder.certificationProfileForVariant(resolvedVariants))
        );
        configuration.addProperty("module_count", modules.size());
        configuration.add("modules", gson.toJsonTree(modules));
        return configuration;
    }

    private static JsonObject requiredObject(JsonObject parent, String key) {
        JsonElement value = parent.get(key);
        if (value == null || !value.isJsonObject()) {
            throw new IllegalArgumentException("required object is missing");
        }
        return value.getAsJsonObject();
    }

    private static JsonObject requireObjectElement(JsonElement value, String label) {
        if (value == null || !value.isJsonObject()) {
            throw new IllegalArgumentException(label + " must be an object");
        }
        return value.getAsJsonObject();
    }

    private static JsonArray requiredArray(JsonObject parent, String key) {
        JsonElement value = parent.get(key);
        if (value == null || !value.isJsonArray()) {
            throw new IllegalArgumentException("required array is missing");
        }
        return value.getAsJsonArray();
    }

    private static JsonArray requiredRunArray(JsonObject plan) {
        JsonElement certificationRuns = plan.get(CERTIFICATION_RUNS_FIELD);
        JsonElement engineeringRuns = plan.get(ENGINEERING_RUNS_FIELD);
        if (certificationRuns != null && engineeringRuns != null) {
            throw new IllegalArgumentException("plan must define exactly one run array");
        }
        if (certificationRuns != null) {
            return requiredArray(plan, CERTIFICATION_RUNS_FIELD);
        }
        return requiredArray(plan, ENGINEERING_RUNS_FIELD);
    }

    private static String requiredString(JsonObject parent, String key) {
        JsonElement value = parent.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("required string is missing");
        }
        String text = value.getAsString();
        if (text.isBlank()) {
            throw new IllegalArgumentException("required string is empty");
        }
        return text;
    }

    private static String optionalString(JsonObject parent, String key, String defaultValue) {
        JsonElement value = parent.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("optional string has an invalid type");
        }
        String text = value.getAsString();
        if (text.isBlank()) {
            throw new IllegalArgumentException("optional string is empty");
        }
        return text;
    }

    private static int requiredInt(JsonObject parent, String key) {
        JsonElement value = parent.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) {
            throw new IllegalArgumentException("required integer is missing");
        }
        return value.getAsInt();
    }
}
