package decompfuncutils.refine.pass;

import java.util.List;

/**
 * One transformation of the refinement pipeline. A pass edits the function's AST in place and
 * reports each change through {@link PassContext}, which is also where it gets its parameters and
 * the verifier from.
 */
public interface RefinePass {
    /** A parameter a pass exposes to configuration. */
    final class Param {
        public enum Type { BOOL, INT, CHOICE }

        public final String key, label, help;
        public final Type type;
        public final Object defaultValue;
        public final List<String> choices;
        public final int min, max;

        private Param(String key, String label, String help, Type type, Object defaultValue, List<String> choices, int min, int max) {
            this.key = key; this.label = label; this.help = help; this.type = type;
            this.defaultValue = defaultValue; this.choices = choices; this.min = min; this.max = max;
        }

        public static Param bool(String key, String label, boolean def, String help) {
            return new Param(key, label, help, Type.BOOL, def, List.of(), 0, 0);
        }

        public static Param integer(String key, String label, int def, int min, int max, String help) {
            return new Param(key, label, help, Type.INT, def, List.of(), min, max);
        }

        public static Param choice(String key, String label, String def, List<String> choices, String help) {
            return new Param(key, label, help, Type.CHOICE, def, choices, 0, 0);
        }
    }

    /** Stable identifier used in configuration. */
    String id();
    String title();
    /** One or two sentences: what the pass undoes and how it justifies it. */
    String description();
    default boolean enabledByDefault() { return true; }
    default List<Param> params() { return List.of(); }

    /** Apply the pass. Returns true when it changed the AST. */
    boolean run(PassContext ctx);
}
