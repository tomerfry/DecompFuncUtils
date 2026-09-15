package decompfuncutils.symbolic;

import com.microsoft.z3.*;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;
import java.math.BigInteger;
import java.util.*;

/**
 * Bounded DFS over raw instruction p-code. State bytes are immutable Z3 terms;
 * each fork owns its register/memory maps, constraints, and instruction cursor.
 * Unsupported behavior terminates a path, never substitutes an unconstrained value.
 */
public final class SymbolicExplorer {
    private static final int MAX_STORED_BYTES = 16384;
    private record Input(String name, Address address, int size, String register) {}
    private record Seed(Address address, byte[] bytes) {}

    private final Program program;
    private final Function function;
    private final Address entry;
    private final Set<Address> targets, avoids;
    private final Register spReg, pcReg;
    private final BigInteger stackPointer;
    private final Map<Register, BigInteger> registers = new LinkedHashMap<>();
    private final List<Seed> memory = new ArrayList<>();
    private final List<Input> inputs = new ArrayList<>();
    private final int maxStates, maxSteps, maxVisits, maxOps, timeoutMs, solverTimeoutMs;
    private final Map<String, Integer> stops = new LinkedHashMap<>();
    private final List<Map<String, Object>> diagnostics = new ArrayList<>();
    private final Map<Address, Instruction> instructions = new HashMap<>();
    private Context ctx;
    private Solver solver;
    private SymbolicArithmetic arithmetic;
    private final Map<Input, BitVecExpr> symbols = new LinkedHashMap<>();
    private long deadline, started;
    private int statesCreated = 1, ops, checks, unsat, replayFailures;
    private boolean incomplete;

    private static final class State {
        Address pc;
        int index = -1, steps;
        final Map<Address, BitVecExpr> bytes = new HashMap<>();
        final List<BoolExpr> constraints = new ArrayList<>();
        final List<Map<String, Object>> branches = new ArrayList<>();
        final Map<Address, Integer> visits = new HashMap<>();
        State(Address pc) { this.pc = pc; }
        State(State other) {
            pc = other.pc; index = other.index; steps = other.steps;
            bytes.putAll(other.bytes); constraints.addAll(other.constraints);
            branches.addAll(other.branches); visits.putAll(other.visits);
        }
    }

    public SymbolicExplorer(Program program, Map<String, Object> args) {
        this.program = program;
        if (!program.getLanguage().getProcessor().toString().equalsIgnoreCase("x86")
                || program.getLanguage().isBigEndian()
                || (program.getDefaultPointerSize() != 4 && program.getDefaultPointerSize() != 8)) {
            throw new IllegalArgumentException("Initial explorer supports little-endian x86/x64 programs only");
        }
        requireKeys(args, Set.of("entry", "targetAddresses", "avoidAddresses", "stackPointer", "registers", "memory",
            "symbolicInputs", "maxStates", "maxStepsPerPath", "maxVisitsPerAddress", "maxPcodeOps", "timeoutMs", "solverTimeoutMs"));
        entry = address(args.get("entry"));
        function = program.getFunctionManager().getFunctionContaining(entry);
        if (function == null || program.getListing().getInstructionAt(entry) == null) {
            throw new IllegalArgumentException("entry must be an instruction in a defined function");
        }
        targets = addresses(args.get("targetAddresses"), 1);
        avoids = addresses(args.getOrDefault("avoidAddresses", List.of()), 0);
        if (!Collections.disjoint(targets, avoids)) throw new IllegalArgumentException("Targets and avoids must not overlap");
        spReg = program.getCompilerSpec().getStackPointer();
        pcReg = program.getLanguage().getProgramCounter();
        if (spReg == null || pcReg == null) throw new IllegalArgumentException("Language lacks SP/PC registers");
        stackPointer = number(args.get("stackPointer"));
        if (stackPointer.signum() <= 0 || stackPointer.bitLength() > spReg.getBitLength()) {
            throw new IllegalArgumentException("stackPointer must be a nonzero unsigned value fitting SP");
        }
        maxStates = limit(args, "maxStates", 128, 512);
        maxSteps = limit(args, "maxStepsPerPath", 2000, 10000);
        maxVisits = limit(args, "maxVisitsPerAddress", 16, 256);
        maxOps = limit(args, "maxPcodeOps", 100000, 500000);
        timeoutMs = limit(args, "timeoutMs", 10000, 60000);
        solverTimeoutMs = limit(args, "solverTimeoutMs", 1000, 5000);
        Set<Address> seededRegisters = new HashSet<>();
        Map<String, Object> seeds = object(args.getOrDefault("registers", Map.of()));
        if (seeds.size() > 128) throw new IllegalArgumentException("At most 128 register seeds");
        for (var e : seeds.entrySet()) {
            Register reg = register(e.getKey());
            rejectControlRegister(reg);
            reserve(seededRegisters, reg.getAddress(), reg.getMinimumByteSize());
            registers.put(reg, number(e.getValue()));
        }
        int seedBytes = 0;
        for (Object raw : array(args.getOrDefault("memory", List.of()), 0, 64)) {
            Map<String, Object> seed = object(raw);
            requireKeys(seed, Set.of("address", "hexBytes"));
            Address at = address(seed.get("address"));
            String hex = string(seed.get("hexBytes")).replaceAll("\\s+", "").replaceFirst("^0[xX]", "");
            if (hex.length() > MAX_STORED_BYTES * 2 || (hex.length() & 1) != 0 || !hex.matches("[0-9a-fA-F]*")) {
                throw new IllegalArgumentException("Invalid or oversized hexBytes");
            }
            byte[] data = HexFormat.of().parseHex(hex);
            seedBytes += data.length;
            if (seedBytes > MAX_STORED_BYTES / 2) throw new IllegalArgumentException("Concrete memory seeds exceed 8192 bytes");
            validateMemoryRange(at, data.length);
            memory.add(new Seed(at, data));
        }
        Set<String> names = new HashSet<>();
        Set<Address> symbolicBytes = new HashSet<>();
        int symbolicSize = 0;
        for (Object raw : array(args.get("symbolicInputs"), 1, 32)) {
            Map<String, Object> in = object(raw);
            requireKeys(in, Set.of("name", "register", "address", "size"));
            String name = string(in.get("name"));
            if (!name.matches("[A-Za-z_][A-Za-z0-9_]{0,63}") || !names.add(name)) {
                throw new IllegalArgumentException("Symbol names must be unique identifiers of at most 64 characters");
            }
            Input input;
            if (in.containsKey("register")) {
                if (in.containsKey("address") || in.containsKey("size")) throw new IllegalArgumentException("Use register OR address/size");
                Register reg = register(string(in.get("register")));
                rejectControlRegister(reg);
                input = new Input(name, reg.getAddress(), reg.getMinimumByteSize(), reg.getName());
            } else {
                Address at = address(in.get("address"));
                int size = limit(in, "size", 0, 64);
                validateMemoryRange(at, size);
                input = new Input(name, at, size, null);
            }
            symbolicSize += input.size;
            if (symbolicSize > 256) throw new IllegalArgumentException("Symbolic inputs exceed 256 bytes");
            reserve(symbolicBytes, input.address, input.size);
            inputs.add(input);
        }
    }

    public Map<String, Object> explore() throws Exception {
        started = System.nanoTime();
        deadline = started + timeoutMs * 1_000_000L;
        List<Map<String, Object>> solutions = new ArrayList<>();
        try (Context context = new Context()) {
            ctx = context;
            solver = ctx.mkSolver();
            arithmetic = new SymbolicArithmetic(ctx);
            State initial = new State(entry);
            write(initial, spReg.getAddress(), spReg.getMinimumByteSize(), arithmetic.constant(stackPointer, spReg.getMinimumByteSize() * 8));
            for (var seed : registers.entrySet()) {
                Register r = seed.getKey();
                write(initial, r.getAddress(), r.getMinimumByteSize(), arithmetic.constant(seed.getValue(), r.getMinimumByteSize() * 8));
            }
            for (Seed seed : memory) {
                for (int i = 0; i < seed.bytes.length; i++) write(initial, seed.address.add(i), 1, ctx.mkBV(seed.bytes[i] & 255, 8));
            }
            for (Input input : inputs) {
                BitVecExpr symbol = ctx.mkBVConst(input.name, input.size * 8);
                symbols.put(input, symbol);
                write(initial, input.address, input.size, symbol);
            }
            Deque<State> pending = new ArrayDeque<>();
            pending.push(initial);
            while (!pending.isEmpty()) {
                State state = pending.pop();
                if (expired()) { stop("timeout", state, true); break; }
                try {
                    Map<String, Object> solution = run(state, pending);
                    if (solution != null) { solutions.add(solution); break; }
                } catch (UnsupportedOperationException e) {
                    stop("unsupported", state, true, e.getMessage());
                }
                if (ops >= maxOps) {
                    if (!pending.isEmpty()) stop("pcode_limit", pending.peek(), true);
                    break;
                }
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", !solutions.isEmpty() ? "found" : incomplete ? "incomplete" : "exhausted");
        out.put("complete", solutions.isEmpty() && !incomplete);
        out.put("entry", entry.toString());
        out.put("function", function.getName());
        out.put("solutions", solutions);
        out.put("statesCreated", statesCreated);
        out.put("pcodeOps", ops);
        out.put("solverChecks", checks);
        out.put("unsatisfiableBranches", unsat);
        out.put("replayFailures", replayFailures);
        out.put("stops", stops);
        out.put("diagnostics", diagnostics);
        out.put("elapsedMs", (System.nanoTime() - started) / 1_000_000L);
        out.put("limits", Map.of("maxStates", maxStates, "maxStepsPerPath", maxSteps,
            "maxVisitsPerAddress", maxVisits, "maxPcodeOps", maxOps, "timeoutMs", timeoutMs, "solverTimeoutMs", solverTimeoutMs));
        out.put("model", "One x86/x64 function; raw integer p-code; concrete memory addresses; " +
            "unseeded ordinary registers are zero; memory comes from explicit seeds or initialized program bytes. " +
            "Calls and unsupported operations stop the path. First replay-verified witness only. " +
            "Exhausted means no target in this model and avoid scope; incomplete is not proof of unreachability.");
        return out;
    }

    private Map<String, Object> run(State s, Deque<State> pending) throws Exception {
        while (true) {
            if (expired()) { stop("timeout", s, true); return null; }
            if (s.index == -1) {
                if (avoids.contains(s.pc)) { stop("avoided", s, false); return null; }
                if (targets.contains(s.pc)) return witness(s);
                if (!function.getBody().contains(s.pc)) { stop("left_function", s, true); return null; }
                if (s.steps >= maxSteps) { stop("step_limit", s, true); return null; }
                if (s.visits.merge(s.pc, 1, Integer::sum) > maxVisits) { stop("visit_limit", s, true); return null; }
                Instruction instruction = instruction(s.pc);
                if (instruction.getDelaySlotDepth() != 0) throw unsupported("delay-slot instruction");
                s.bytes.keySet().removeIf(a -> a.getAddressSpace().isUniqueSpace());
                write(s, pcReg.getAddress(), pcReg.getMinimumByteSize(), arithmetic.constant(
                    BigInteger.valueOf(s.pc.getOffset()), pcReg.getMinimumByteSize() * 8));
                s.steps++;
                s.index = 0;
            }
            Instruction instruction = instruction(s.pc);
            PcodeOp[] code = instruction.getPcode();
            if (s.index == code.length) { jump(s, s.pc.add(instruction.getLength())); continue; }
            if (s.index < 0 || s.index > code.length) throw unsupported("invalid internal p-code branch");
            if (ops >= maxOps) { stop("pcode_limit", s, true); return null; }
            ops++;
            int index = s.index++;
            PcodeOp op = code[index];
            switch (op.getOpcode()) {
                case PcodeOp.CBRANCH -> {
                    BoolExpr condition = (BoolExpr) arithmetic.truth(read(s, op.getInput(1))).simplify();
                    if (condition.isTrue() || condition.isFalse()) {
                        boolean taken = condition.isTrue();
                        trace(s, index, taken);
                        if (taken) branch(s, op.getInput(0), index);
                    } else {
                        // Check both successors against ALL preceding branch constraints.
                        fork(s, pending, op.getInput(0), index, condition, true);
                        fork(s, pending, op.getInput(0), index, ctx.mkNot(condition), false);
                        return null;
                    }
                }
                case PcodeOp.BRANCH -> branch(s, op.getInput(0), index);
                case PcodeOp.BRANCHIND -> jump(s, s.pc.getAddressSpace().getAddress(concrete(read(s, op.getInput(0)), "symbolic jump target")));
                case PcodeOp.RETURN -> { stop("returned", s, false); return null; }
                case PcodeOp.CALL, PcodeOp.CALLIND -> throw unsupported("call requires a callee model at " + s.pc);
                case PcodeOp.CALLOTHER -> throw unsupported("CALLOTHER/userop at " + s.pc);
                case PcodeOp.LOAD -> {
                    Address at = memoryAddress(s, op);
                    write(s, op.getOutput().getAddress(), op.getOutput().getSize(), read(s, at, op.getOutput().getSize()));
                }
                case PcodeOp.STORE -> {
                    Address at = memoryAddress(s, op);
                    int size = op.getInput(2).getSize();
                    for (int i = 0; i < size; i++) rejectCodeWrite(at.add(i));
                    write(s, at, size, read(s, op.getInput(2)));
                }
                default -> {
                    if (op.getOutput() == null) throw unsupported("p-code without output: " + op.getMnemonic());
                    BitVecExpr[] values = new BitVecExpr[op.getNumInputs()];
                    for (int i = 0; i < values.length; i++) values[i] = read(s, op.getInput(i));
                    if (values.length == 0) throw unsupported("p-code without operands: " + op.getMnemonic());
                    write(s, op.getOutput().getAddress(), op.getOutput().getSize(),
                        arithmetic.apply(op.getOpcode(), op.getOutput().getSize() * 8, values));
                }
            }
        }
    }

    private void fork(State source, Deque<State> pending, Varnode target, int index, BoolExpr condition, boolean taken) {
        List<BoolExpr> constraints = new ArrayList<>(source.constraints);
        constraints.add(condition);
        Status status = check(constraints);
        if (status == Status.UNSATISFIABLE) { unsat++; return; }
        if (status != Status.SATISFIABLE) { stop("solver_unknown", source, true, solver.getReasonUnknown()); return; }
        if (statesCreated >= maxStates) { stop("state_limit", source, true); return; }
        State child = new State(source);
        child.constraints.add(condition);
        trace(child, index, taken);
        if (taken) branch(child, target, index);
        pending.push(child);
        statesCreated++;
    }

    private Status check(List<BoolExpr> constraints) {
        checks++;
        solver.reset();
        Params params = ctx.mkParams();
        int remaining = (int) Math.max(1, (deadline - System.nanoTime()) / 1_000_000L);
        params.add("timeout", Math.min(solverTimeoutMs, remaining));
        solver.setParameters(params);
        solver.add(constraints.toArray(BoolExpr[]::new));
        return solver.check();
    }

    private Map<String, Object> witness(State s) throws Exception {
        Status status = check(s.constraints);
        if (status != Status.SATISFIABLE) { stop("solver_unknown", s, true); return null; }
        Model model = solver.getModel();
        Map<String, String> values = new LinkedHashMap<>();
        Map<Input, BigInteger> concrete = new LinkedHashMap<>();
        Map<String, String> replayRegisters = new LinkedHashMap<>();
        for (var e : registers.entrySet()) replayRegisters.put(e.getKey().getName(), hex(e.getValue(), e.getKey().getMinimumByteSize()));
        List<Map<String, String>> replayMemory = new ArrayList<>();
        for (Seed seed : memory) replayMemory.add(Map.of("address", seed.address.toString(), "hexBytes", HexFormat.of().formatHex(seed.bytes)));
        for (var e : symbols.entrySet()) {
            BigInteger value = ((BitVecNum) model.eval(e.getValue(), true)).getBigInteger();
            Input in = e.getKey();
            concrete.put(in, value);
            values.put(in.name, hex(value, in.size));
            if (in.register != null) replayRegisters.put(in.register, hex(value, in.size));
            else replayMemory.add(Map.of("address", in.address.toString(), "hexBytes", HexFormat.of().formatHex(littleEndian(value, in.size))));
        }
        Map<String, Object> replay = replay(concrete, s.pc);
        if (!Boolean.TRUE.equals(replay.get("verified"))) {
            replayFailures++;
            stop("replay_failed", s, true, replay.toString());
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("targetAddress", s.pc.toString());
        out.put("inputs", values);
        out.put("branches", s.branches);
        out.put("steps", s.steps);
        out.put("replay", replay);
        out.put("emulateArguments", Map.of("entry", entry.toString(), "stackPointer", "0x" + stackPointer.toString(16),
            "registers", replayRegisters, "memory", replayMemory, "maxSteps", maxSteps,
            "stopAddresses", java.util.stream.Stream.concat(targets.stream(), avoids.stream()).map(Address::toString).toList()));
        return out;
    }

    private Map<String, Object> replay(Map<Input, BigInteger> values, Address target) throws Exception {
        EmulatorHelper emulator = new EmulatorHelper(program);
        try {
            emulator.writeRegister(spReg, stackPointer);
            for (var e : registers.entrySet()) emulator.writeRegister(e.getKey(), e.getValue());
            for (Seed seed : memory) emulator.writeMemory(seed.address, seed.bytes);
            for (var e : values.entrySet()) {
                Input in = e.getKey();
                if (in.register != null) emulator.writeRegister(in.register, e.getValue());
                else emulator.writeMemory(in.address, littleEndian(e.getValue(), in.size));
            }
            emulator.writeRegister(pcReg, entry.getOffset());
            for (int steps = 0; steps <= maxSteps; steps++) {
                Address pc = emulator.getExecutionAddress();
                if (expired()) return Map.of("verified", false, "reason", "timeout");
                if (avoids.contains(pc)) return Map.of("verified", false, "reason", "avoid reached", "pc", pc.toString());
                if (pc.equals(target)) return Map.of("verified", true, "steps", steps, "pc", pc.toString());
                if (targets.contains(pc)) return Map.of("verified", false, "reason", "different target reached", "pc", pc.toString());
                if (steps == maxSteps) break;
                if (!emulator.step(TaskMonitor.DUMMY)) return Map.of("verified", false, "reason", String.valueOf(emulator.getLastError()));
            }
            return Map.of("verified", false, "reason", "step limit");
        } catch (Exception e) {
            return Map.of("verified", false, "reason", e.toString());
        } finally {
            emulator.dispose();
        }
    }

    private BitVecExpr read(State s, Varnode var) {
        if (var.isConstant()) return arithmetic.constant(BigInteger.valueOf(var.getOffset()), var.getSize() * 8);
        return read(s, var.getAddress(), var.getSize());
    }

    private BitVecExpr read(State s, Address at, int size) {
        if (size < 1 || size > 64) throw unsupported("value size outside 1..64 bytes");
        BitVecExpr result = null;
        for (int i = size - 1; i >= 0; i--) {
            Address a = at.add(i);
            BitVecExpr value = s.bytes.get(a);
            if (value == null) {
                if (a.getAddressSpace().isRegisterSpace()) value = ctx.mkBV(0, 8);
                else if (a.getAddressSpace().isMemorySpace()) {
                    try { value = ctx.mkBV(program.getMemory().getByte(a) & 255, 8); }
                    catch (Exception e) { throw unsupported("uninitialized memory read at " + a); }
                } else throw unsupported("undefined p-code temporary at " + a);
            }
            result = result == null ? value : ctx.mkConcat(result, value);
        }
        return (BitVecExpr) result.simplify();
    }

    private void write(State s, Address at, int size, BitVecExpr value) {
        if (size < 1 || size > 64 || value.getSortSize() != size * 8) throw unsupported("invalid storage width");
        for (int i = 0; i < size; i++) {
            Address a = at.add(i);
            if (!s.bytes.containsKey(a) && s.bytes.size() >= MAX_STORED_BYTES) throw unsupported("state storage limit");
            s.bytes.put(a, (BitVecExpr) ctx.mkExtract(i * 8 + 7, i * 8, value).simplify());
        }
    }

    private Address memoryAddress(State s, PcodeOp op) {
        AddressSpace space = program.getAddressFactory().getAddressSpace((int) op.getInput(0).getOffset());
        if (space == null || !space.isMemorySpace() || space.getAddressableUnitSize() != 1) throw unsupported("non-byte memory space");
        return space.getAddress(concrete(read(s, op.getInput(1)), "symbolic memory address"));
    }

    private long concrete(BitVecExpr value, String reason) {
        if (!(value.simplify() instanceof BitVecNum num) || num.getBigInteger().bitLength() > 64) throw unsupported(reason);
        return num.getBigInteger().longValue();
    }

    private void branch(State s, Varnode target, int index) {
        if (target.isConstant()) s.index = index + (int) target.getOffset();
        else jump(s, target.getAddress());
    }

    private static void jump(State s, Address pc) { s.pc = pc; s.index = -1; }
    private void trace(State s, int index, boolean taken) {
        if (s.branches.size() >= 4096) throw unsupported("branch trace limit");
        s.branches.add(Map.of("pc", s.pc.toString(), "pcodeIndex", index, "taken", taken));
    }
    private boolean expired() { return Thread.currentThread().isInterrupted() || System.nanoTime() >= deadline; }
    private void stop(String reason, State s, boolean partial) { stop(reason, s, partial, reason); }
    private void stop(String reason, State s, boolean partial, String detail) {
        incomplete |= partial;
        stops.merge(reason, 1, Integer::sum);
        if (partial && diagnostics.size() < 20) diagnostics.add(Map.of("pc", s.pc.toString(), "reason", reason, "detail", detail));
    }
    private Instruction instruction(Address pc) {
        Instruction ins = instructions.computeIfAbsent(pc, a -> program.getListing().getInstructionAt(a));
        if (ins == null) throw unsupported("no instruction at " + pc);
        return ins;
    }
    private static UnsupportedOperationException unsupported(String reason) { return SymbolicArithmetic.unsupported(reason); }

    private Address address(Object value) {
        Address at = McpUtil.parseAddress(string(value), program);
        if (at == null || !at.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) {
            throw new IllegalArgumentException("Address must be in the program's default memory space");
        }
        return at;
    }
    private Set<Address> addresses(Object value, int min) {
        Set<Address> result = new LinkedHashSet<>();
        for (Object raw : array(value, min, 64)) {
            Address at = address(raw);
            if (!function.getBody().contains(at) || program.getListing().getInstructionAt(at) == null) {
                throw new IllegalArgumentException("Targets/avoids must be instruction addresses in the entry function: " + at);
            }
            result.add(at);
        }
        return result;
    }
    private Register register(String name) {
        Register r = program.getRegister(name);
        if (r == null || r.isProcessorContext() || r.getBitLength() != r.getMinimumByteSize() * 8 || r.getMinimumByteSize() > 64) {
            throw new IllegalArgumentException("Unknown or non-byte register: " + name);
        }
        return r;
    }
    private void rejectControlRegister(Register r) {
        if (r.getBaseRegister().equals(spReg.getBaseRegister()) || r.getBaseRegister().equals(pcReg.getBaseRegister())) {
            throw new IllegalArgumentException("PC/SP cannot be seeded through registers or symbolicInputs; use entry/stackPointer");
        }
    }
    private void validateMemoryRange(Address at, int size) {
        try {
            if (size > 0) at.addNoWrap(size - 1);
            for (int i = 0; i < size; i++) rejectCodeWrite(at.add(i));
        } catch (Exception e) { throw new IllegalArgumentException("Invalid memory seed range: " + e.getMessage(), e); }
    }
    private void rejectCodeWrite(Address at) {
        MemoryBlock block = program.getMemory().getBlock(at);
        if (block != null && block.isExecute()) throw unsupported("executable memory write at " + at);
    }
    private static void reserve(Set<Address> used, Address at, int size) {
        for (int i = 0; i < size; i++) if (!used.add(at.add(i))) throw new IllegalArgumentException("Overlapping input/register ranges at " + at);
    }
    private static String string(Object value) {
        if (!(value instanceof String s) || s.isBlank()) throw new IllegalArgumentException("Expected a nonempty string");
        return s;
    }
    private static BigInteger number(Object value) {
        String text = string(value).strip();
        boolean negative = text.startsWith("-");
        if (negative) text = text.substring(1);
        BigInteger n = text.startsWith("0x") || text.startsWith("0X")
            ? new BigInteger(text.substring(2), 16) : new BigInteger(text, 10);
        return negative ? n.negate() : n;
    }
    private static int limit(Map<String, Object> args, String key, int def, int max) {
        Object raw = args.getOrDefault(key, def);
        if (!(raw instanceof Number)) throw new IllegalArgumentException(key + " must be an integer");
        int n;
        try { n = new java.math.BigDecimal(raw.toString()).intValueExact(); }
        catch (ArithmeticException | NumberFormatException e) { throw new IllegalArgumentException(key + " must be an integer"); }
        if (n < 1 || n > max) throw new IllegalArgumentException(key + " must be between 1 and " + max);
        return n;
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map)) throw new IllegalArgumentException("Expected an object");
        return (Map<String, Object>) value;
    }
    private static List<?> array(Object value, int min, int max) {
        if (!(value instanceof List<?> list) || list.size() < min || list.size() > max) {
            throw new IllegalArgumentException("Expected an array of " + min + ".." + max + " items");
        }
        return list;
    }
    private static void requireKeys(Map<String, Object> value, Set<String> allowed) {
        for (String key : value.keySet()) if (!allowed.contains(key)) throw new IllegalArgumentException("Unknown field: " + key);
    }
    private static String hex(BigInteger value, int size) { return "0x" + value.mod(BigInteger.ONE.shiftLeft(size * 8)).toString(16); }
    private static byte[] littleEndian(BigInteger value, int size) {
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) bytes[i] = value.shiftRight(i * 8).byteValue();
        return bytes;
    }
}
