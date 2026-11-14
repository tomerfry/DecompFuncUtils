package decompfuncutils.refine.pass;

import java.util.List;

/** The passes the engine knows, in their default order. */
public final class RefinePasses {
    private static final List<RefinePass> ALL = List.of(
        new SimplifyPass(),
        new OpaquePass(),
        new SelectPass(),
        new FoldTempsPass(),
        new RulesPass(),
        new LoopsPass(),
        new LoopIdiomPass(),
        new StoresPass(),
        new InlinePass(),
        new ConstCallPass(),
        new DeadStorePass());

    private RefinePasses() {}

    public static List<RefinePass> all() { return ALL; }

    public static RefinePass byId(String id) {
        for (RefinePass p : ALL) if (p.id().equals(id)) return p;
        return null;
    }
}
