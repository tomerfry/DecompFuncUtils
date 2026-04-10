package decompfuncutils.flowrecorder;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serializes a recorded flow to markdown. The output is structured so that:
 *   - humans can read and hand-edit it
 *   - an agent can parse each step's fenced ```json block and feed it
 *     back through the MCP protocol handler deterministically
 */
public class FlowMarkdownWriter {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final DateTimeFormatter TS_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public static void write(
            Path file,
            String name,
            String description,
            String sourceProgram,
            List<FlowStep> steps,
            FlowTemplatizer templatizer) throws IOException {

        StringBuilder sb = new StringBuilder();

        // --- YAML frontmatter ---------------------------------------------------
        sb.append("---\n");
        sb.append("name: ").append(yamlEscape(name)).append('\n');
        sb.append("description: ").append(yamlEscape(description)).append('\n');
        sb.append("source_program: ").append(yamlEscape(sourceProgram)).append('\n');
        sb.append("recorded_at: ").append(TS_FMT.format(java.time.Instant.now())).append('\n');
        sb.append("step_count: ").append(steps.size()).append('\n');

        Map<String, FlowTemplatizer.Placeholder> placeholders = templatizer.getPlaceholders();
        if (!placeholders.isEmpty()) {
            sb.append("inputs:\n");
            for (FlowTemplatizer.Placeholder p : placeholders.values()) {
                sb.append("  - name: ").append(p.name).append('\n');
                sb.append("    kind: ").append(p.kind).append('\n');
                if (p.description != null && !p.description.isEmpty()) {
                    sb.append("    description: ").append(yamlEscape(p.description)).append('\n');
                }
                sb.append("    example: ").append(yamlEscape(p.capturedValue)).append('\n');
            }
        }
        sb.append("---\n\n");

        // --- Heading & overview -------------------------------------------------
        sb.append("# ").append(escapeMd(name)).append("\n\n");
        if (description != null && !description.isEmpty()) {
            sb.append(escapeMd(description)).append("\n\n");
        }

        // --- Placeholder reference table ----------------------------------------
        if (!placeholders.isEmpty()) {
            sb.append("## Placeholders\n\n");
            sb.append("| Placeholder | Kind | Captured From | Description |\n");
            sb.append("|-------------|------|---------------|-------------|\n");
            for (FlowTemplatizer.Placeholder p : placeholders.values()) {
                sb.append("| `").append(p.name).append("` ")
                  .append("| ").append(p.kind).append(' ')
                  .append("| `").append(escapeTableCell(p.capturedValue)).append("` ")
                  .append("| ").append(escapeTableCell(p.description == null ? "" : p.description)).append(" |\n");
            }
            sb.append('\n');
        }

        // --- Steps --------------------------------------------------------------
        sb.append("## Steps\n\n");
        int i = 1;
        for (FlowStep step : steps) {
            sb.append("### Step ").append(i++).append(": ").append(escapeMd(step.getSummary())).append("\n\n");
            sb.append("- **Tool:** `").append(step.getToolName()).append("`\n");
            sb.append("- **Recorded at:** ")
              .append(TS_FMT.format(step.getTimestamp()))
              .append("\n\n");

            Map<String, Object> block = new LinkedHashMap<>();
            block.put("tool", step.getToolName());
            block.put("arguments", step.getTemplatedArgs());
            sb.append("```json\n");
            sb.append(GSON.toJson(block));
            sb.append("\n```\n\n");
        }

        Files.writeString(file, sb.toString());
    }

    private static String yamlEscape(String s) {
        if (s == null) return "\"\"";
        if (s.isEmpty()) return "\"\"";
        // Quote anything that contains characters YAML parsers treat specially.
        if (s.matches(".*[:#\\[\\]{}\"'&*?|>%@`!\\\\\\n].*")) {
            return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        return s;
    }

    private static String escapeMd(String s) {
        if (s == null) return "";
        return s.replace("\n", " ");
    }

    private static String escapeTableCell(String s) {
        if (s == null) return "";
        return s.replace("|", "\\|").replace("\n", " ");
    }
}
