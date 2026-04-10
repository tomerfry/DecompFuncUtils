package decompfuncutils.flowrecorder;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One recorded reverser action, normalized into the same shape the MCP tool
 * layer would accept. Holds both the concrete arguments (what actually
 * happened) and the templated arguments (with placeholders) so the step can
 * be replayed generically by an agent.
 */
public class FlowStep {

    private final String toolName;
    private final Map<String, Object> rawArgs;
    private Map<String, Object> templatedArgs;
    private final String summary;
    private final Instant timestamp;

    public FlowStep(String toolName, Map<String, Object> rawArgs, String summary) {
        this.toolName = toolName;
        this.rawArgs = new LinkedHashMap<>(rawArgs);
        this.templatedArgs = new LinkedHashMap<>(rawArgs);
        this.summary = summary;
        this.timestamp = Instant.now();
    }

    public String getToolName() { return toolName; }
    public Map<String, Object> getRawArgs() { return rawArgs; }
    public Map<String, Object> getTemplatedArgs() { return templatedArgs; }
    public void setTemplatedArgs(Map<String, Object> templatedArgs) { this.templatedArgs = templatedArgs; }
    public String getSummary() { return summary; }
    public Instant getTimestamp() { return timestamp; }
}
