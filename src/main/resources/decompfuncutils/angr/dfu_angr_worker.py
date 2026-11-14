#!/usr/bin/env python3
"""
DecompFuncUtils angr worker.

A long-lived helper process started by the Ghidra extension (decompfuncutils.angr.AngrWorker).
It speaks line-delimited JSON over stdin/stdout: one request object per line in, one response
object per line out. Everything angr or its dependencies print goes to stderr, which the Java
side keeps as a diagnostic tail.

The worker never opens the original executable. Ghidra exports the program's memory image
(image.bin + image.json, see decompfuncutils.angr.AngrImage) and this loads it with CLE's blob
backend, so every address here is the address Ghidra shows, patches made in Ghidra are honoured,
and anything Ghidra can load can be emulated. Ghidra also decides where arguments live (its
parameter storage) and which addresses are imports; this side only places values and hooks.

Requests:
  {"id": n, "op": "ping"}
  {"id": n, "op": "call", "imageDir": "...", "imageKey": "...", "spec": {...}}
  {"id": n, "op": "imports", "imageDir": "...", "imageKey": "..."}
  {"id": n, "op": "check_hook", "name": "...", "code": "..."}      -> compile only
  {"id": n, "op": "drop", "imageKey": "..."}
  {"id": n, "op": "dbg_open", "imageDir": "...", "spec": {...}}      -> a live session
  {"id": n, "op": "dbg_step", "session": s, "kind": "into|over|out|continue", ...}
  {"id": n, "op": "dbg_state", "session": s}
  {"id": n, "op": "dbg_edit", "session": s, "action": "concretize|symbolize|set|select|drop", ...}
  {"id": n, "op": "dbg_hooks", "session": s, "spec": {...}}          -> re-install hooks
  {"id": n, "op": "dbg_close", "session": s}
  {"id": n, "op": "shutdown"}
"""
from __future__ import annotations

import bisect
import inspect
import itertools
import json
import logging
import os
import re
import sys
import time
import traceback

PROTOCOL_VERSION = 1

# The protocol owns the real stdout. Point fd 1 at stderr so that nothing a library prints,
# from Python or from native code, can land in the middle of a response line.
_proto_fd = os.dup(1)
os.dup2(2, 1)
_PROTO = os.fdopen(_proto_fd, "w", encoding="utf-8", newline="\n")
sys.stdout = sys.stderr


def emit(obj):
    _PROTO.write(json.dumps(obj, separators=(",", ":")) + "\n")
    _PROTO.flush()


try:
    import angr
    import archinfo
    import cle

    try:
        import claripy
    except ImportError:  # angr 10 ships claripy inside the angr package
        from angr import claripy
except Exception as exc:  # pylint: disable=broad-except
    emit({"ready": False, "error": "%s: %s" % (type(exc).__name__, exc),
          "python": sys.version.split()[0], "executable": sys.executable})
    sys.exit(2)

try:  # where angr's stdio models keep the file descriptor inside a FILE
    from cle.backends.externs.simdata.io_file import io_file_data_for_arch
except Exception:  # pylint: disable=broad-except
    io_file_data_for_arch = None

for _name in ("angr", "cle", "pyvex", "claripy", "archinfo"):
    logging.getLogger(_name).setLevel(logging.ERROR)

o = angr.options

MAX_LOG_ENTRIES = 300
MAX_WRITE_RANGES = 256
MAX_PREVIEW = 64
MAX_DUMP = 4096
MAX_EAGER_ZERO_MAP = 256 * 1024 * 1024
ALLOC_LIMIT = 64 * 1024 * 1024
PAGE = 0x1000


class SpecError(Exception):
    """The request asked for something that cannot be done; the message is for the caller."""


def h(value):
    """Parse an address or integer sent as a hex/decimal string or a JSON number."""
    if isinstance(value, bool):
        raise SpecError("expected a number, got a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != int(value):
            raise SpecError("expected an integer, got %r" % value)
        return int(value)
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        try:
            return int(text, 0)
        except ValueError:
            raise SpecError("not a number: %r" % value) from None
    raise SpecError("expected a number, got %r" % (value,))


def attrs(state):
    """Inspect attributes: state.inspect.attrs on angr 10, state.inspect itself before."""
    return getattr(state.inspect, "attrs", state.inspect)


def printable(data):
    return all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in data)


def text_of(data):
    return data.decode("ascii", "replace")


# -------------------------------------------------------------------------------------------
# Image: one exported Ghidra program, loaded once and reused across calls
# -------------------------------------------------------------------------------------------

def make_arch(spec):
    name = spec["name"]
    big = spec.get("endian") == "big"
    end = archinfo.Endness.BE if big else archinfo.Endness.LE
    table = {
        "AMD64": lambda: archinfo.ArchAMD64(),
        "X86": lambda: archinfo.ArchX86(),
        "ARMEL": lambda: archinfo.ArchARMEL(end),
        "ARMHF": lambda: archinfo.ArchARMHF(end),
        "ARMCortexM": lambda: archinfo.ArchARMCortexM(end),
        "AARCH64": lambda: archinfo.ArchAArch64(end),
        "MIPS32": lambda: archinfo.ArchMIPS32(end),
        "MIPS64": lambda: archinfo.ArchMIPS64(end),
        "PPC32": lambda: archinfo.ArchPPC32(end),
        "PPC64": lambda: archinfo.ArchPPC64(end),
    }
    try:
        if name in table:
            return table[name]()
        return archinfo.arch_from_id(name, "big" if big else "little")
    except Exception as exc:  # pylint: disable=broad-except
        raise SpecError("angr has no architecture for %r (Ghidra language %s): %s. Pass 'arch' to "
                        "name one angr knows (e.g. AMD64, X86, ARMEL, ARMCortexM, AARCH64, MIPS32, "
                        "PPC32)." % (name, spec.get("language"), exc)) from None


_SIM_LIBRARIES = ("libc", "posix", "glibc", "msvcr", "win32", "ntdll", "linux_loader")


def find_simprocedure(name):
    """angr's model of a library function, or None when it has none."""
    candidates = [name]
    if name.startswith("__isoc99_"):
        candidates.append(name[len("__isoc99_"):])
    if name.startswith("_") and not name.startswith("__"):
        candidates.append(name[1:])  # leading-underscore decorated imports
    for candidate in candidates:
        for lib in _SIM_LIBRARIES:
            procs = angr.SIM_PROCEDURES.get(lib)
            if procs and candidate in procs:
                return procs[candidate]
    return None


class ExternalStub(angr.SimProcedure):
    """
    Stands in for a function nothing can model: an import angr has no SimProcedure for, or any
    function the caller asked to stub. Returns a fixed value, zero, or (in symbolic runs) a fresh
    unconstrained value whose solution is reported back as an assumption about the environment.
    """

    # pylint: disable=arguments-differ
    def run(self, *args, dfu_value=None, dfu_symbolic=False, dfu_noreturn=False):
        bits = self.state.arch.bits
        if dfu_noreturn:
            self.exit(0)
            return None
        if dfu_value is not None:
            return claripy.BVV(dfu_value & ((1 << bits) - 1), bits)
        if dfu_symbolic:
            return fresh_symbol(self.state, str(self.display_name) + "_ret", bits, str(self.display_name))
        return claripy.BVV(0, bits)


_SYMBOL_COUNTER = itertools.count(1)


def fresh_symbol(state, base, bits, origin=None):
    """
    A new unconstrained value with a name a person can type back (to concretize it), recorded on
    the state so results can say what value it had to take.
    """
    name = "%s_%d" % (re.sub(r"[^A-Za-z0-9_]", "_", base), next(_SYMBOL_COUNTER))
    value = claripy.BVS(name, bits, explicit_name=True)
    assumed = state.globals.get("dfu_assumed", ())
    if len(assumed) < MAX_LOG_ENTRIES:
        state.globals["dfu_assumed"] = assumed + ((origin or name, value),)
    return value


class HookError(angr.errors.SimError):
    """A user-written Python hook raised; the message carries what and where."""


class CompiledHook:
    """
    A replacement written in Python by the user or by an agent over MCP:

        def hook(ctx, path, flags):     # parameters after ctx receive the call's arguments
            ctx.log("open", ctx.string(path))
            return 3                    # the return value; None means 0

    See HookContext for what ctx offers.
    """

    def __init__(self, name, code):
        self.name = name
        namespace = {"angr": angr, "claripy": claripy, "archinfo": archinfo,
                     "__name__": "dfu_hook_" + re.sub(r"\W", "_", name)}
        try:
            exec(compile(code, "<hook %s>" % name, "exec"), namespace)  # pylint: disable=exec-used
        except SyntaxError as exc:
            raise SpecError("hook '%s' does not compile: %s (line %s)" % (name, exc.msg, exc.lineno)) from None
        except Exception as exc:  # pylint: disable=broad-except
            raise SpecError("hook '%s' failed while loading: %s: %s" % (name, type(exc).__name__, exc)) from None
        func = namespace.get("hook")
        if not callable(func):
            raise SpecError("hook '%s' must define a function named hook: def hook(ctx, ...)" % name)
        params = list(inspect.signature(func).parameters.values())
        positional = [p for p in params
                      if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)]
        if not positional:
            raise SpecError("hook '%s': hook() must take the context as its first parameter" % name)
        self.func = func
        self.nargs = len(positional) - 1
        self.varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)


class HookContext:
    """What a Python hook is handed: the call's arguments and the machine state, in plain terms."""

    def __init__(self, state, name, args, call):
        self.state = state          # the angr SimState, for anything not wrapped here
        self.name = name
        self.args = list(args)      # raw bit-vectors, one per argument
        self.arch = state.arch
        self.angr = angr
        self.claripy = claripy
        self._call = call

    # -- values --
    def is_symbolic(self, value):
        return hasattr(value, "symbolic") and value.symbolic

    def value(self, value):
        """A Python int for a concrete value; for a symbolic one, one value it can take."""
        if isinstance(value, int):
            return value
        return self.state.solver.eval(value)

    def arg(self, index):
        """Argument as an int when concrete, as a bit-vector when symbolic."""
        if index >= len(self.args):
            raise IndexError("hook '%s' asked for argument %d but only %d were read; add parameters "
                             "to hook() to read more" % (self.name, index, len(self.args)))
        value = self.args[index]
        return value if self.is_symbolic(value) else self.state.solver.eval(value)

    def symbolic(self, name=None, bits=None):
        """A fresh unknown value; return it to make the result unconstrained."""
        return fresh_symbol(self.state, name or (self.name + "_ret"), bits or self.arch.bits, self.name)

    def constrain(self, *conditions):
        self.state.add_constraints(*conditions)

    # -- memory --
    def read(self, address, size):
        data = self.state.memory.load(self.value(address), size)
        return self.state.solver.eval(data, cast_to=bytes)

    def read_int(self, address, size=None, signed=False):
        size = size or self.arch.bytes
        number = self.state.solver.eval(
            self.state.memory.load(self.value(address), size, endness=self.arch.memory_endness))
        if signed and number >> (size * 8 - 1):
            number -= 1 << (size * 8)
        return number

    def string(self, address, limit=4096):
        out = bytearray()
        base = self.value(address)
        while len(out) < limit:
            chunk = self.read(base + len(out), 1)
            if chunk == b"\0":
                break
            out += chunk
        return out.decode("utf-8", "replace")

    def write(self, address, data):
        if isinstance(data, str):
            data = data.encode("utf-8") + b"\0"
        self.state.memory.store(self.value(address), data)

    def write_int(self, address, value, size=None):
        size = size or self.arch.bytes
        if isinstance(value, int):
            value = claripy.BVV(value & ((1 << (size * 8)) - 1), size * 8)
        self.state.memory.store(self.value(address), value, endness=self.arch.memory_endness)

    def alloc(self, size):
        """Fresh zeroed heap memory, as malloc would return."""
        address = self.state.heap.allocate(size)
        address = address if isinstance(address, int) else self.state.solver.eval(address)
        self.state.memory.store(address, b"\0" * max(1, size))
        return address

    # -- registers --
    def reg(self, name):
        value = self.state.registers.load(self._call.register_name(name))
        return value if value.symbolic else self.state.solver.eval(value)

    def set_reg(self, name, value):
        name = self._call.register_name(name)
        bits = self.arch.registers[name][1] * 8
        if isinstance(value, int):
            value = claripy.BVV(value & ((1 << bits) - 1), bits)
        self.state.registers.store(name, Call.fit(value, bits))

    # -- reporting --
    def log(self, *parts):
        """Shows up in the call trace, in order with the calls around it."""
        self._call.log(self.state, {"log": " ".join(str(p) for p in parts), "hook": self.name})


def invoke_hook(hook, ctx, named):
    try:
        return hook.func(ctx, *named)
    except (angr.errors.SimError, SpecError):
        raise
    except Exception as exc:  # pylint: disable=broad-except
        where = ""
        tb = exc.__traceback__
        while tb is not None:
            if tb.tb_frame.f_code.co_filename.startswith("<hook "):
                where = " at line %d" % tb.tb_lineno
            tb = tb.tb_next
        raise HookError("Python hook '%s' raised %s%s: %s" % (hook.name, type(exc).__name__, where, exc)) from None


class PythonHook(angr.SimProcedure):
    """Runs a CompiledHook in place of a function and returns to the caller with its result."""

    # pylint: disable=arguments-differ
    def run(self, *args, dfu_hook=None, dfu_call=None):
        ctx = HookContext(self.state, dfu_hook.name, args, dfu_call)
        count = len(args) if dfu_hook.varargs else dfu_hook.nargs
        result = invoke_hook(dfu_hook, ctx, [ctx.arg(i) for i in range(min(count, len(args)))])
        bits = self.state.arch.bits
        if result is None:
            return claripy.BVV(0, bits)
        if isinstance(result, bool):
            result = int(result)
        if isinstance(result, int):
            return claripy.BVV(result & ((1 << bits) - 1), bits)
        if hasattr(result, "size"):
            return Call.fit(result, bits)
        raise HookError("Python hook '%s' returned %r; return an int, a bit-vector or None"
                        % (dfu_hook.name, result))


class Image:
    def __init__(self, directory, arch_override=None):
        with open(os.path.join(directory, "image.json"), "r", encoding="utf-8") as fh:
            self.manifest = manifest = json.load(fh)
        arch_spec = dict(manifest["arch"])
        if arch_override:
            arch_spec["name"] = arch_override
        self.arch = make_arch(arch_spec)
        segments = [(s["offset"], h(s["addr"]), s["size"]) for s in manifest["segments"]]
        if not segments:
            raise SpecError("the program has no initialized memory to emulate")
        base = min(addr for _, addr, _ in segments)
        self.project = angr.Project(
            os.path.join(directory, manifest["image"]),
            main_opts={"backend": "blob", "arch": self.arch, "base_addr": base,
                       "entry_point": base, "segments": segments},
            auto_load_libs=False)

        # Every range Ghidra has a block for, initialized or not.
        regions = [(h(s["addr"]), h(s["addr"]) + s["size"], s.get("name", "")) for s in manifest["segments"]]
        self.zero = [(h(z["addr"]), z["size"], z.get("name", "")) for z in manifest.get("zero", [])]
        regions += [(a, a + n, name) for a, n, name in self.zero]
        regions.sort()
        self.regions = regions
        self.region_starts = [r[0] for r in regions]

        self.externals = manifest.get("externals", [])
        # Imported variables (stdout, environ, a library's globals): Ghidra gives each a slot in
        # its EXTERNAL block, which is exported as zero memory so reading one does not fault.
        self.external_data = manifest.get("externalData", [])
        # Imports reached through a pointer slot Ghidra never filled in (a PE import table)
        # get an address of their own for the slot to point at.
        self.synthetic = {}
        for ext in self.externals:
            if ext.get("slots"):
                self.synthetic[ext["name"]] = self.project.loader.extern_object.allocate()
        self.cc = self._library_cc()

    def _library_cc(self):
        """The convention library models read their arguments with, when it is not angr's default."""
        compiler = (self.manifest.get("compiler") or "").lower()
        if self.arch.name == "AMD64" and compiler in ("windows", "clangwindows"):
            cls = getattr(angr.calling_conventions, "SimCCMicrosoftAMD64", None)
            if cls is not None:
                return cls(self.arch)
        return None

    def in_image(self, addr):
        i = bisect.bisect_right(self.region_starts, addr) - 1
        return i >= 0 and addr < self.regions[i][1]

    def region_end(self, addr):
        i = bisect.bisect_right(self.region_starts, addr) - 1
        if i >= 0 and addr < self.regions[i][1]:
            return self.regions[i][1]
        return None

    def overlaps(self, start, end):
        for r_start, r_end, _ in self.regions:
            if start < r_end and r_start < end:
                return True
        ext = self.project.loader.extern_object
        return start <= ext.max_addr and ext.min_addr < end

    def pick_base(self, size, taken):
        """An address range clear of the image, the stack and everything already handed out."""
        bits = self.arch.bits
        if bits >= 64:
            candidates = [0x600000000000 + i * 0x10000000000 for i in range(16)]
        elif bits == 32:
            candidates = [0xC0000000, 0xD0000000, 0xA0000000, 0x90000000, 0x60000000, 0x50000000,
                          0x30000000, 0x20000000, 0xE0000000, 0x70000000, 0x40000000]
        else:
            candidates = [0x4000, 0x8000, 0xC000]
        stack_top = self.arch.initial_sp + 0x10000
        stack_bottom = self.arch.initial_sp - 0x1000000
        for base in candidates:
            end = base + size
            if end > (1 << bits):
                continue
            if base < stack_top and stack_bottom < end:
                continue
            if any(base < t_end and t_start < end for t_start, t_end in taken):
                continue
            if self.overlaps(base, end):
                continue
            taken.append((base, end))
            return base
        raise SpecError("no free address range of %#x bytes outside the program image" % size)


# -------------------------------------------------------------------------------------------
# One call
# -------------------------------------------------------------------------------------------

class Call:
    def __init__(self, image, spec):
        self.image = image
        self.project = image.project
        self.arch = image.arch
        self.spec = spec
        self.ptr_bits = self.arch.bits
        self.ptr_bytes = self.arch.bytes
        self.strict = bool(spec.get("strictMemory", True))
        self.warnings = []
        self.symbols = []       # (name, bv, kind) for every symbolic input, in creation order
        self.buffers = []       # pointer arguments: what was allocated where
        self.taken = []
        self.alloc_base = None
        self.alloc_next = None
        self.alloc_mapped = None
        self.known = []         # (start, end) ranges worth previewing as data
        self.hook_names = {}
        self.unmodelled = set()  # imports angr has no model for, stubbed
        self.external_symbols = {}  # imported variables made unknown: symbol name -> value
        self.inline_hooks = set()
        self.python_hooks = []
        self.unmodelled_called = set()
        self.state = None
        self.symbolic_run = False

    # ---- memory handed to the callee ----

    def alloc(self, size):
        size = max(1, size)
        if self.alloc_base is None:
            self.alloc_base = self.image.pick_base(ALLOC_LIMIT, self.taken)
            self.alloc_next = self.alloc_base + 0x100
            self.alloc_mapped = self.alloc_base
            self.known.append((self.alloc_base, self.alloc_base + ALLOC_LIMIT))
        addr = (self.alloc_next + 15) & ~15
        end = addr + size
        if end > self.alloc_base + ALLOC_LIMIT:
            raise SpecError("argument buffers exceed %d MB in total" % (ALLOC_LIMIT >> 20))
        # 16 bytes of slack between buffers, so a one-off overrun does not land in a neighbour.
        self.alloc_next = end + 16
        if self.strict:
            need = (self.alloc_next + PAGE - 1) & ~(PAGE - 1)
            if need > self.alloc_mapped:
                self.state.memory.map_region(self.alloc_mapped, need - self.alloc_mapped, 3)
                self.alloc_mapped = need
        return addr

    def new_symbol(self, name, bits, kind):
        taken = {n for n, _, _ in self.symbols}
        base = name
        n = 2
        while name in taken:
            name = "%s_%d" % (base, n)
            n += 1
        bv = claripy.BVS(name, bits, explicit_name=True)
        self.symbols.append((name, bv, kind))
        self.symbolic_run = True
        return bv

    def scalar(self, spec, bits, label):
        """
        A value for a register, stack slot or struct field: an integer, a symbolic integer, or a
        pointer to freshly allocated memory holding what the spec describes.
        """
        if isinstance(spec, (int, float, str)) and not isinstance(spec, bool):
            spec = {"int": spec}
        if not isinstance(spec, dict):
            raise SpecError("%s: expected a number or an object, got %r" % (label, spec))

        if "int" in spec:
            size_bits = int(spec["size"]) * 8 if "size" in spec else bits
            return claripy.BVV(h(spec["int"]) & ((1 << size_bits) - 1), size_bits)
        if "symbolicInt" in spec:
            raw = spec["symbolicInt"]
            size_bits = bits if raw in (True, None, 0) else int(h(raw))
            if size_bits <= 0 or size_bits > 4096:
                raise SpecError("%s: symbolicInt needs a bit width between 1 and 4096" % label)
            bv = self.new_symbol(str(spec.get("name") or label), size_bits, "int")
            if "min" in spec:
                self.state.add_constraints(claripy.UGE(bv, h(spec["min"])))
            if "max" in spec:
                self.state.add_constraints(claripy.ULE(bv, h(spec["max"])))
            return bv
        return claripy.BVV(self.pointer(spec, label), self.ptr_bits)

    def pointer(self, spec, label):
        """Allocate what a pointer argument points at; returns its address."""
        state = self.state
        record = {"arg": label}
        if "string" in spec:
            data = str(spec["string"]).encode("utf-8") + b"\0"
            addr = self.alloc(len(data))
            state.memory.store(addr, data)
            record.update(kind="string", size=len(data), initial=data)
        elif "bytes" in spec:
            data = bytes.fromhex(str(spec["bytes"]).replace(" ", ""))
            addr = self.alloc(len(data))
            if data:
                state.memory.store(addr, data)
            record.update(kind="bytes", size=len(data), initial=data)
        elif "buffer" in spec:
            size = int(h(spec["buffer"]))
            if size < 0 or size > ALLOC_LIMIT:
                raise SpecError("%s: buffer size out of range" % label)
            fill = int(h(spec.get("fill", 0))) & 0xFF
            data = bytes([fill]) * size
            addr = self.alloc(size)
            if data:
                state.memory.store(addr, data)
            record.update(kind="buffer", size=size, initial=data)
        elif "symbolicBytes" in spec:
            size = int(h(spec["symbolicBytes"]))
            if size <= 0 or size > 65536:
                raise SpecError("%s: symbolicBytes needs a size between 1 and 65536" % label)
            terminated = bool(spec.get("nullTerminated", False))
            addr = self.alloc(size + (1 if terminated else 0))
            bv = self.new_symbol(str(spec.get("name") or label), size * 8, "bytes")
            state.memory.store(addr, bv)
            if terminated:
                state.memory.store(addr + size, b"\0")
            if spec.get("printable"):
                for i in range(size):
                    byte = bv.get_byte(i)
                    state.add_constraints(claripy.UGE(byte, 0x20), claripy.ULE(byte, 0x7E))
            record.update(kind="symbolicBytes", size=size + (1 if terminated else 0), initial=None)
        elif "struct" in spec:
            fields = spec["struct"]
            if not isinstance(fields, list) or not fields:
                raise SpecError("%s: struct needs a non-empty list of fields" % label)
            pieces = []
            for i, field in enumerate(fields):
                flabel = "%s.%d" % (label, i)
                if isinstance(field, dict) and "raw" in field:
                    pieces.append((claripy.BVV(bytes.fromhex(str(field["raw"]).replace(" ", ""))), False))
                elif isinstance(field, dict) and "pad" in field:
                    pieces.append((claripy.BVV(0, int(h(field["pad"])) * 8), False))
                else:
                    # Integers default to 4 bytes inside a struct; pointers are pointer-sized.
                    is_int = not isinstance(field, dict) or "int" in field or "symbolicInt" in field
                    width = 32 if is_int and not (isinstance(field, dict) and "size" in field) else self.ptr_bits
                    pieces.append((self.scalar(field, width, flabel), True))
            total = sum(bv.size() for bv, _ in pieces) // 8
            addr = self.alloc(total)
            offset = 0
            for bv, endian in pieces:
                if bv.size() == 0:
                    continue
                state.memory.store(addr + offset, bv,
                                   endness=self.arch.memory_endness if endian else archinfo.Endness.BE)
                offset += bv.size() // 8
            record.update(kind="struct", size=total, initial=None)
        else:
            raise SpecError("%s: unknown argument form %s. Use a number, or one of int, string, bytes, "
                            "buffer, struct, symbolicInt, symbolicBytes." % (label, sorted(spec)))
        record["address"] = addr
        self.buffers.append(record)
        return addr

    # ---- placing values ----

    def register_name(self, name):
        if name in self.arch.registers:
            return name
        lowered = name.lower()
        if lowered in self.arch.registers:
            return lowered
        raise SpecError("angr has no register named %r on %s" % (name, self.arch.name))

    def put(self, loc, bv, label):
        size = int(loc.get("size") or (bv.size() // 8))
        bits = size * 8
        if bv.size() > bits:
            bv = bv[bits - 1:0]
        elif bv.size() < bits:
            bv = bv.zero_extend(bits - bv.size())
        if "reg" in loc:
            name = self.register_name(loc["reg"])
            reg_size = self.arch.registers[name][1]
            if size > reg_size:
                bv = bv[reg_size * 8 - 1:0]
            self.state.registers.store(name, bv)
        elif "stack" in loc:
            self.state.memory.store(self.state.regs.sp + int(h(loc["stack"])), bv,
                                    endness=self.arch.memory_endness)
        else:
            raise SpecError("%s: Ghidra gave no usable storage (%s). Place it yourself with "
                            "'registers' or 'memory'." % (label, loc.get("unsupported", loc)))

    # ---- hooks ----

    def install_hooks(self):
        spec = self.spec
        project = self.project
        overrides = spec.get("externalStubs") or {}
        policy = spec.get("unmodelled")
        symbolic_default = (policy == "symbolic") if policy else self.symbolic_run
        by_name = {}
        for ext in self.image.externals:
            name = ext["name"]
            addrs = [h(a) for a in ext.get("addrs", [])]
            if name in self.image.synthetic:
                addrs.append(self.image.synthetic[name])
            if not addrs:
                continue
            by_name[name] = (ext, addrs)
            for addr in addrs:
                project.hook(addr, self.external_procedure(ext, overrides.get(name), symbolic_default),
                             replace=True)
                self.hook_names[addr] = name
        for stub in spec.get("stubs") or []:
            addr = h(stub["addr"])
            name = stub.get("name") or hex(addr)
            params = int(stub.get("params", -1))
            project.hook(addr, ExternalStub(display_name=name, num_args=params if params >= 0 else 4,
                                            cc=self.image.cc, **self.stub_kwargs(stub.get("returns"))),
                         replace=True)
            self.hook_names[addr] = name

        # Python replacements go on last, so they win over models and stubs alike.
        for item in spec.get("pyHooks") or []:
            name = item.get("name") or "hook"
            hook = CompiledHook(name, item.get("code") or "")
            params = -1
            addrs = [h(a) for a in item.get("addrs") or []]
            display = name
            if item.get("external"):
                if item["external"] not in by_name:
                    self.warnings.append("Python hook '%s' targets import '%s', which this program does "
                                         "not call through any address." % (name, item["external"]))
                    continue
                ext, addrs = by_name[item["external"]]
                params = int(ext.get("params", -1))
                display = item["external"]
                self.unmodelled.discard(display)
            if item.get("kind") == "inline":
                skip = int(h(item.get("skip", 0)))
                for addr in addrs:
                    project.hook(addr, self.inline_hook(hook), length=skip, replace=True)
                    self.inline_hooks.add(addr)
                self.python_hooks.append(name)
                continue
            num_args = min(max(hook.nargs, params if params >= 0 else 4), 10)
            for addr in addrs:
                project.hook(addr, PythonHook(display_name=display, num_args=num_args, cc=self.image.cc,
                                              dfu_hook=hook, dfu_call=self), replace=True)
                self.hook_names[addr] = display
            self.python_hooks.append(name)

    def inline_hook(self, hook):
        """A hook that runs at an address and then lets execution carry on (or skips bytes)."""
        def run(state):
            invoke_hook(hook, HookContext(state, hook.name, [], self), [])
        return run

    def stub_kwargs(self, returns):
        if returns is None:
            return {}
        if isinstance(returns, str) and returns.strip().lower() == "symbolic":
            self.symbolic_run = True
            return {"dfu_symbolic": True}
        return {"dfu_value": h(returns)}

    def external_procedure(self, ext, override, symbolic_default):
        name = ext["name"]
        params = int(ext.get("params", -1))
        num_args = min(params, 8) if params >= 0 else 4
        if override is not None:
            return ExternalStub(display_name=name, num_args=num_args, cc=self.image.cc,
                                **self.stub_kwargs(override))
        cls = find_simprocedure(name)
        if cls is not None:
            return cls(display_name=name, cc=self.image.cc)
        self.unmodelled.add(name)
        if ext.get("noreturn"):
            return ExternalStub(display_name=name, num_args=num_args, cc=self.image.cc, dfu_noreturn=True)
        return ExternalStub(display_name=name, num_args=num_args, cc=self.image.cc,
                            dfu_symbolic=symbolic_default)

    def remove_hooks(self):
        for addr in list(self.hook_names) + list(self.inline_hooks):
            try:
                self.project.unhook(addr)
            except Exception:  # pylint: disable=broad-except
                pass
        self.hook_names.clear()
        self.inline_hooks.clear()
        self.python_hooks = []

    # ---- observation ----

    def is_known(self, addr):
        if self.image.in_image(addr):
            return True
        return any(start <= addr < end for start, end in self.known)

    def known_end(self, addr):
        end = self.image.region_end(addr)
        if end is not None:
            return end
        for start, stop in self.known:
            if start <= addr < stop:
                return stop
        return None

    def load_bytes(self, state, addr, length):
        """Concrete bytes at addr, or None when unreadable or symbolic."""
        try:
            bv = state.memory.load(addr, length, inspect=False, disable_actions=True)
            if bv.symbolic:
                return None
            return state.solver.eval(bv, cast_to=bytes)
        except Exception:  # pylint: disable=broad-except
            return None

    def string_at(self, state, addr, min_in_image=1):
        """
        A printable C string at addr, for annotating pointers in traces and results.
        min_in_image asks for more evidence inside the program image, where a pointer to code
        would otherwise read as a short "string" (x86-64 prologues are printable bytes).
        """
        if addr < PAGE or not self.is_known(addr):
            return None
        end = self.known_end(addr)
        length = min(MAX_PREVIEW, end - addr) if end else MAX_PREVIEW
        if length <= 0:
            return None
        data = self.load_bytes(state, addr, length)
        if data is None:
            return None
        nul = data.find(b"\0")
        text = data if nul < 0 else data[:nul]
        if not text or not printable(text):
            return None
        if len(text) < min_in_image and self.image.in_image(addr):
            return None
        return text_of(text) + ("" if nul >= 0 else "...")

    def render(self, state, value):
        """An argument or return value as it appears in the call trace."""
        if value is None:
            return None
        if isinstance(value, int):
            value = claripy.BVV(value & ((1 << self.ptr_bits) - 1), self.ptr_bits)
        if not hasattr(value, "symbolic"):
            return str(value)
        if value.symbolic:
            return "<symbolic>"
        number = state.solver.eval(value)
        text = self.string_at(state, number)
        if text is not None:
            return "%#x %s" % (number, json.dumps(text))
        return "%#x" % number

    def log(self, state, entry):
        entries = state.globals.get("dfu_log", ())
        if len(entries) < MAX_LOG_ENTRIES:
            state.globals["dfu_log"] = entries + (entry,)
        else:
            state.globals["dfu_dropped"] = state.globals.get("dfu_dropped", 0) + 1

    def note_transfers(self, states):
        """
        Record the calls and returns the last step made. angr's own "call" breakpoint is not
        raised by every engine version, while the jump kind and source of the step that produced
        a state are always in its history.
        """
        for state in states:
            kind = state.history.jumpkind
            if kind == "Ijk_Call":
                depth = state.globals.get("dfu_depth", 0) + 1
                state.globals["dfu_depth"] = depth
                site = state.history.jump_source
                if site is None:
                    site = state.history.addr
                state.globals["dfu_site"] = site
                try:
                    target = state.addr
                except Exception:  # pylint: disable=broad-except
                    continue  # symbolic target; reported as a symbolic jump
                if self.project.is_hooked(target) or (target & ~1) in self.hook_names:
                    continue  # reported with its arguments and result once the procedure has run
                self.log(state, {"call": "%#x" % target,
                                 "from": "%#x" % site if site is not None else None, "depth": depth})
            elif kind == "Ijk_Ret":
                state.globals["dfu_depth"] = max(0, state.globals.get("dfu_depth", 0) - 1)

    def on_simprocedure(self, state):
        a = attrs(state)
        proc = a.simprocedure
        addr = a.simprocedure_addr
        if proc is None or addr is None:
            return
        name = self.hook_names.get(addr)
        if name is None:
            name = self.hook_names.get(addr & ~1)
        # Models call each other internally (strcmp runs strlen); only the hooked one is a call
        # the program made.
        if name is None or getattr(proc, "display_name", None) != name:
            return
        entry = {"call": name, "args": [self.render(state, x) for x in (proc.arguments or [])]}
        result = a.simprocedure_result
        if result is not None:
            entry["returned"] = self.render(state, result)
        site = state.globals.get("dfu_site")
        if site is not None:
            entry["from"] = "%#x" % site
        entry["depth"] = state.globals.get("dfu_depth", 1)
        if isinstance(proc, PythonHook):
            entry["python"] = True
        elif isinstance(proc, ExternalStub):
            entry["stubbed"] = True
            if name in self.unmodelled:
                self.unmodelled_called.add(name)
        self.log(state, entry)

    def on_write(self, state):
        a = attrs(state)
        addr = a.mem_write_address
        if addr is None:
            return
        if hasattr(addr, "symbolic"):
            if addr.symbolic:
                return
            addr = state.solver.eval(addr)
        if not self.image.in_image(addr):
            return
        length = a.mem_write_length
        if hasattr(length, "symbolic"):
            length = None if length.symbolic else state.solver.eval(length)
        if length is None:
            expr = a.mem_write_expr
            length = expr.size() // 8 if hasattr(expr, "size") else 1
        writes = state.globals.get("dfu_writes", ())
        if len(writes) < MAX_WRITE_RANGES * 8:
            state.globals["dfu_writes"] = writes + ((addr, int(length)),)

    # ---- setup ----

    def build_state(self):
        spec = self.spec
        image = self.image
        arch = self.arch
        entry = h(spec["entry"])

        add = {o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        if self.strict:
            add.add(o.STRICT_PAGE_ACCESS)
        kwargs = {}
        stdin = spec.get("stdin")
        symbolic_requested = bool(spec.get("symbolicRun"))
        if stdin is not None:
            kwargs["stdin"] = angr.SimFileStream(name="stdin", content=self.blob(stdin), has_end=True)
        elif not symbolic_requested:
            kwargs["stdin"] = angr.SimFileStream(name="stdin", content=b"", has_end=True)

        # Head-room above the entry stack pointer for arguments passed on the stack.
        stack_base = arch.initial_sp - 0x4000
        self.known.append((arch.initial_sp - 0x800000, arch.initial_sp + PAGE))
        state = self.project.factory.call_state(entry, ret_addr=self.project.simos.return_deadend,
                                                stack_base=stack_base, add_options=add, **kwargs)
        self.state = state
        self.symbolic_run = symbolic_requested

        heap_size = 0x2000000
        heap_base = image.pick_base(heap_size, self.taken)
        state.register_plugin("heap", angr.SimHeapBrk(heap_base=heap_base, heap_size=heap_size))
        self.known.append((heap_base, heap_base + heap_size))

        if self.strict:
            mapped = 0
            skipped = []
            for addr, size, name in image.zero:
                if mapped + size > MAX_EAGER_ZERO_MAP:
                    skipped.append(name or hex(addr))
                    continue
                start = addr & ~(PAGE - 1)
                end = (addr + size + PAGE - 1) & ~(PAGE - 1)
                for page in range(start, end, PAGE):
                    try:
                        state.memory.map_region(page, PAGE, 3)
                    except Exception:  # pylint: disable=broad-except
                        pass  # shares a page with an initialized block
                mapped += size
            if skipped:
                self.warnings.append("Uninitialized blocks too large to map were left out, so access to "
                                     "them faults: %s. Use strictMemory=false to read them as zero."
                                     % ", ".join(skipped))
        self.setup_thread_pointer()

        # Slots Ghidra leaves unresolved (PE import tables) point at the import's hook.
        for ext in image.externals:
            target = image.synthetic.get(ext["name"])
            if target is None:
                continue
            for slot in ext.get("slots", []):
                state.memory.store(h(slot), claripy.BVV(target, self.ptr_bits),
                                   endness=arch.memory_endness)

        # With unknown imports symbolic, imported variables are unknown too rather than zero.
        # They are not announced as symbols here: a program imports many it never reads, and a
        # debugger lists an unknown once the path depends on it (see DebugSession.symbol_table).
        if spec.get("unmodelled") == "symbolic":
            streams = {item["addr"] for item in image.manifest.get("stdio") or []}
            for item in image.external_data[:256]:
                if item["addr"] in streams:
                    continue  # given a real FILE below
                name = "ext_" + re.sub(r"[^A-Za-z0-9_]", "_", str(item["name"]))
                if name in self.external_symbols:
                    continue
                value = claripy.BVS(name, self.ptr_bits, explicit_name=True)
                self.external_symbols[name] = value
                state.memory.store(h(item["addr"]), value, endness=arch.memory_endness)
            if self.external_symbols:
                self.symbolic_run = True

        self.setup_stdio()

        for i, arg in enumerate(spec.get("args") or []):
            label = "arg%d" % i
            loc = arg.get("loc") or {}
            bits = int(loc.get("size") or self.ptr_bytes) * 8
            self.put(loc, self.scalar(arg.get("value"), bits, label), label)

        for name, value in (spec.get("registers") or {}).items():
            reg = self.register_name(name)
            bits = arch.registers[reg][1] * 8
            self.put({"reg": reg, "size": bits // 8}, self.scalar(value, bits, "reg_" + reg), reg)

        for i, seed in enumerate(spec.get("memory") or []):
            self.seed_memory(seed, "mem%d" % i)

        return state

    def setup_stdio(self):
        """
        Points the program's stdin / stdout / stderr variables at FILE objects angr's stdio
        models understand. They are imported variables, so without this they hold NULL and the
        first fprintf(stderr, ...) - which is how most programs report anything - faults.
        """
        items = self.image.manifest.get("stdio") or []
        if not items or io_file_data_for_arch is None:
            return
        try:
            layout = io_file_data_for_arch(self.arch)
        except Exception:  # pylint: disable=broad-except
            return
        made = {}
        for item in items:
            fd = int(item["fd"])
            if fd not in made:
                size = int(layout.get("size", 256))
                addr = self.alloc(size)
                self.state.memory.store(addr, b"\0" * size)
                self.state.memory.store(addr + layout["fd"], claripy.BVV(fd, 32),
                                        endness=self.arch.memory_endness)
                made[fd] = addr
            self.state.memory.store(h(item["addr"]), claripy.BVV(made[fd], self.ptr_bits),
                                    endness=self.arch.memory_endness)

    def setup_thread_pointer(self):
        """Give thread-local reads (stack canaries, errno) somewhere mapped to land."""
        state = self.state
        try:
            if self.arch.name in ("AMD64", "AARCH64"):
                base = self.image.pick_base(0x2000, self.taken)
                if self.strict:
                    state.memory.map_region(base, 0x2000, 3)
                if self.arch.name == "AMD64":
                    state.regs.fs = base + 0x1000
                else:
                    state.regs.tpidr_el0 = base + 0x1000
        except Exception:  # pylint: disable=broad-except
            pass

    def blob(self, value):
        if isinstance(value, dict):
            if "bytes" in value:
                return bytes.fromhex(str(value["bytes"]).replace(" ", ""))
            if "string" in value:
                return str(value["string"]).encode("utf-8")
        return str(value).encode("utf-8")

    def seed_memory(self, seed, label):
        state = self.state
        addr = h(seed["addr"])
        if "bytes" in seed:
            state.memory.store(addr, bytes.fromhex(str(seed["bytes"]).replace(" ", "")))
        elif "string" in seed:
            state.memory.store(addr, str(seed["string"]).encode("utf-8") + b"\0")
        elif "symbolicBytes" in seed:
            size = int(h(seed["symbolicBytes"]))
            state.memory.store(addr, self.new_symbol(str(seed.get("name") or label), size * 8, "bytes"))
        elif "int" in seed or "symbolicInt" in seed:
            size = int(seed.get("size") or self.ptr_bytes)
            spec = dict(seed)
            spec.pop("size", None)
            spec.pop("addr", None)
            state.memory.store(addr, self.fit(self.scalar(spec, size * 8, label), size * 8),
                               endness=self.arch.memory_endness)
        elif "pointer" in seed:
            state.memory.store(addr, claripy.BVV(self.pointer(seed["pointer"], label), self.ptr_bits),
                               endness=self.arch.memory_endness)
        else:
            raise SpecError("memory[%s]: give one of bytes, string, int, symbolicInt, symbolicBytes, "
                            "pointer" % label)

    @staticmethod
    def fit(bv, bits):
        if bv.size() > bits:
            return bv[bits - 1:0]
        if bv.size() < bits:
            return bv.zero_extend(bits - bv.size())
        return bv

    # ---- running ----

    def run(self):
        started = time.time()
        state = self.build_state()
        self.install_hooks()
        try:
            return self.explore(state, started)
        finally:
            self.remove_hooks()

    def explore(self, state, started):
        spec = self.spec
        arch = self.arch
        ret_addr = self.project.simos.return_deadend
        thumb_mask = ~1 if arch.name.startswith("ARM") else ~0
        find = {h(a) & thumb_mask for a in spec.get("find") or []}
        avoid = {h(a) & thumb_mask for a in spec.get("avoid") or []}
        want_return = h(spec["wantReturn"]) if spec.get("wantReturn") is not None else None
        max_steps = int(spec.get("maxSteps") or 100000)
        max_paths = int(spec.get("maxPaths") or 8)
        deadline = started + (int(spec.get("timeoutMs") or 30000) / 1000.0)
        trace = spec.get("trace", "calls")

        tracing = trace != "none"
        if tracing:
            state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.on_simprocedure)
        if spec.get("trackWrites", True):
            state.inspect.b("mem_write", when=angr.BP_AFTER, action=self.on_write)

        simgr = self.project.factory.simgr(state, save_unconstrained=True)
        for stash in ("returned", "found", "avoided", "pruned"):
            simgr.stashes[stash] = []

        steps = 0
        stop = "completed"
        while True:
            for s in list(simgr.active):
                addr = s.addr
                if addr == ret_addr:
                    dest = "returned"
                elif (addr & thumb_mask) in find:
                    dest = "found"
                elif (addr & thumb_mask) in avoid:
                    dest = "avoided"
                else:
                    continue
                simgr.active.remove(s)
                simgr.stashes[dest].append(s)
            if simgr.found:
                stop = "found"
                break
            if not simgr.active:
                break
            if not find and want_return is None and len(simgr.returned) >= max_paths:
                stop = "path_limit"
                break
            if steps >= max_steps:
                stop = "max_steps"
                break
            if time.time() >= deadline:
                stop = "timeout"
                break
            steps += len(simgr.active)
            simgr.step()
            if tracing:
                self.note_transfers(simgr.active)
            limit = max(max_paths * 8, 64)
            if len(simgr.active) > limit:
                simgr.stashes["pruned"].extend(simgr.active[limit:])
                del simgr.active[limit:]

        return self.report(simgr, stop, steps, started, want_return, max_paths, bool(find))

    # ---- reporting ----

    def report(self, simgr, stop, steps, started, want_return, max_paths, finding):
        paths = []
        counts = {}

        def count(kind, n=1):
            if n:
                counts[kind] = counts.get(kind, 0) + n

        for s in simgr.found:
            count("found")
            paths.append(self.describe(s, "found"))
        returned_unwanted = 0
        for s in simgr.returned:
            if want_return is not None:
                narrowed = self.constrain_return(s, want_return)
                if narrowed is None:
                    returned_unwanted += 1
                    continue
                s = narrowed
            count("returned")
            if not finding:
                paths.append(self.describe(s, "returned"))
        count("returnedOtherValue", returned_unwanted)
        for record in simgr.errored:
            count("faulted")
            if not finding and want_return is None:
                paths.append(self.describe(record.state, "fault", error=record.error))
        for s in simgr.deadended:
            count("exited")
            if not finding and want_return is None:
                paths.append(self.describe(s, "exited"))
        for s in simgr.unconstrained:
            count("symbolicJump")
            if not finding and want_return is None:
                paths.append(self.describe(s, "symbolic_jump"))
        for s in simgr.active:
            count("unfinished")
            if not finding and want_return is None:
                paths.append(self.describe(s, "unfinished"))
        count("avoided", len(simgr.avoided))
        count("pruned", len(simgr.pruned))

        result = {
            "mode": "symbolic" if self.symbolic_run else "concrete",
            "stopReason": stop,
            "blocksExecuted": steps,
            "elapsedMs": int((time.time() - started) * 1000),
        }
        total = len(paths)
        paths = paths[:max_paths]
        if (finding or want_return is not None) and not paths:
            result["outcome"] = "no_path"
            if finding:
                result["note"] = "No explored path reached a 'find' address."
            else:
                result["note"] = "No explored path returns %#x." % want_return
            result["pathCounts"] = counts
        elif len(paths) == 1 and total == 1:
            result.update(paths[0])
            if len(counts) > 1 or self.symbolic_run:
                result["pathCounts"] = counts
        else:
            result["paths"] = paths
            result["pathCounts"] = counts
            if total > len(paths):
                result["pathsOmitted"] = total - len(paths)
        if self.unmodelled_called:
            result["unmodelledExternals"] = sorted(self.unmodelled_called)
            result["unmodelledNote"] = (
                "angr has no model for these imports, so they did nothing and returned %s. Give them "
                "a return value with 'stubs' if the result depends on them."
                % ("an unconstrained value" if self.symbolic_run else "0"))
        if self.python_hooks:
            result["pythonHooks"] = self.python_hooks
        if self.warnings:
            result["warnings"] = self.warnings
        return result

    def constrain_return(self, state, want):
        loc = self.spec.get("ret")
        if not loc or "reg" not in loc:
            raise SpecError("wantReturn needs a return register; Ghidra gave none for this function")
        value = self.return_bv(state, loc)
        narrowed = state.copy()
        narrowed.add_constraints(value == (want & ((1 << value.size()) - 1)))
        return narrowed if narrowed.satisfiable() else None

    def return_bv(self, state, loc):
        name = self.register_name(loc["reg"])
        size = int(loc.get("size") or self.arch.registers[name][1])
        size = min(size, self.arch.registers[name][1])
        return state.registers.load(name, size)

    def value_report(self, state, bv, as_pointer=True):
        out = {}
        bits = bv.size()
        if bv.symbolic:
            try:
                values = state.solver.eval_upto(bv, 2)
            except Exception as exc:  # pylint: disable=broad-except
                return {"symbolic": True, "error": str(exc)}
            if len(values) != 1:
                # Depends on the inputs: show one value it can take and the range.
                out["symbolic"] = True
                try:
                    out["example"] = "%#x" % values[0]
                    out["min"] = "%#x" % state.solver.min(bv)
                    out["max"] = "%#x" % state.solver.max(bv)
                except Exception as exc:  # pylint: disable=broad-except
                    out["error"] = str(exc)
                return out
            number = values[0]
        else:
            number = state.solver.eval(bv)
        out["hex"] = "%#x" % number
        signed = number - (1 << bits) if number >> (bits - 1) else number
        out["signed"] = signed
        if bits > 32 and number >> 31 == 1:
            out["signed32"] = number - (1 << 32)
        if as_pointer and bits >= self.ptr_bits:
            text = self.string_at(state, number)
            if text is not None:
                out["string"] = text
        return out

    def describe(self, state, outcome, error=None):
        spec = self.spec
        out = {"outcome": outcome}
        try:
            out["stoppedAt"] = "%#x" % state.addr
        except Exception:  # pylint: disable=broad-except
            out["stoppedAt"] = None

        if outcome == "returned":
            out.pop("stoppedAt", None)
            loc = spec.get("ret")
            if loc and "reg" in loc:
                value = self.value_report(state, self.return_bv(state, loc))
                if loc.get("type"):
                    value["type"] = loc["type"]
                out["returnValue"] = value
        elif outcome == "fault":
            out["fault"] = self.fault_report(error)
        elif outcome == "symbolic_jump":
            out["note"] = "Execution reached a jump whose target depends on symbolic input, so it was not followed."
        elif outcome == "exited":
            out["note"] = "The program terminated itself (exit/abort or a function Ghidra marks as non-returning)."

        if self.symbols:
            inputs = self.solve_inputs(state)
            if inputs:
                out["inputs"] = inputs

        assumed = state.globals.get("dfu_assumed", ())
        if assumed:
            rows = []
            for name, bv in assumed:
                try:
                    rows.append({"call": name, "symbol": next(iter(bv.variables), None),
                                 "returns": "%#x" % state.solver.eval(bv)})
                except Exception:  # pylint: disable=broad-except
                    pass
            if rows:
                out["assumedReturns"] = rows

        for fd, key in ((1, "stdout"), (2, "stderr")):
            try:
                data = state.posix.dumps(fd)
            except Exception:  # pylint: disable=broad-except
                data = b""
            if data:
                out[key] = text_of(data) if printable(data) else {"hex": data[:MAX_DUMP].hex()}

        buffers = self.buffer_report(state)
        if buffers:
            out["buffers"] = buffers
        writes = self.write_report(state)
        if writes:
            out["globalWrites"] = writes
        dumps = self.memory_report(state)
        if dumps:
            out["memory"] = dumps
        log = state.globals.get("dfu_log", ())
        if log:
            out["calls"] = list(log)
            dropped = state.globals.get("dfu_dropped", 0)
            if dropped:
                out["callsOmitted"] = dropped
        return out

    def fault_report(self, error):
        info = {"type": type(error).__name__, "message": str(error)}
        addr = getattr(error, "addr", None)
        if isinstance(addr, int):
            info["address"] = "%#x" % addr
        reason = getattr(error, "reason", None)
        if reason:
            info["reason"] = str(reason)
        if type(error).__name__ == "SimSegfaultException":
            if isinstance(addr, int) and addr < PAGE:
                info["hint"] = ("A NULL (or near-NULL) pointer was dereferenced. An argument, struct "
                                "field or global the function follows was left zero - pass a buffer or "
                                "seed it with 'memory'.")
            else:
                info["hint"] = ("The function touched memory Ghidra has no block for. Seed the pointer "
                                "it followed, or pass strictMemory=false to read unmapped memory as zero.")
        return info

    def solve_inputs(self, state):
        inputs = {}
        for name, bv, kind in self.symbols:
            entry = {}
            try:
                if kind == "bytes":
                    data = state.solver.eval(bv, cast_to=bytes)
                    entry["hex"] = data.hex()
                    nul = data.find(b"\0")
                    text = data if nul < 0 else data[:nul]
                    if text and printable(text):
                        entry["string"] = text_of(text)
                else:
                    number = state.solver.eval(bv)
                    bits = bv.size()
                    entry["hex"] = "%#x" % number
                    entry["signed"] = number - (1 << bits) if number >> (bits - 1) else number
                if bv.size() <= 512:
                    entry["unique"] = len(state.solver.eval_upto(bv, 2)) == 1
            except Exception as exc:  # pylint: disable=broad-except
                entry["error"] = "%s: %s" % (type(exc).__name__, exc)
            inputs[name] = entry
        try:
            stdin = state.posix.dumps(0)
            if stdin and self.spec.get("stdin") is None:
                inputs["stdin"] = {"hex": stdin[:MAX_DUMP].hex()}
                if printable(stdin):
                    inputs["stdin"]["string"] = text_of(stdin[:MAX_DUMP])
        except Exception:  # pylint: disable=broad-except
            pass
        return inputs

    def data_report(self, state, addr, size):
        """Final contents of a range, as hex plus a string when it reads as one."""
        out = {}
        shown = min(size, MAX_DUMP)
        try:
            bv = state.memory.load(addr, shown, inspect=False, disable_actions=True)
        except Exception as exc:  # pylint: disable=broad-except
            return {"error": "%s: %s" % (type(exc).__name__, exc)}
        if bv.symbolic:
            out["symbolic"] = True
            try:
                data = state.solver.eval(bv, cast_to=bytes)
            except Exception as exc:  # pylint: disable=broad-except
                return {"symbolic": True, "error": str(exc)}
        else:
            data = state.solver.eval(bv, cast_to=bytes)
        out["hex"] = data.hex()
        nul = data.find(b"\0")
        text = data if nul < 0 else data[:nul]
        if text and printable(text):
            out["string"] = text_of(text)
        if shown < size:
            out["truncatedTo"] = shown
        return out, data

    def buffer_report(self, state):
        rows = []
        for record in self.buffers:
            row = {"arg": record["arg"], "address": "%#x" % record["address"], "size": record["size"]}
            if record["size"]:
                reported = self.data_report(state, record["address"], record["size"])
                if isinstance(reported, tuple):
                    content, data = reported
                    row.update(content)
                    initial = record.get("initial")
                    if initial is not None:
                        row["changed"] = data != initial[:len(data)]
                else:
                    row.update(reported)
            rows.append(row)
        return rows

    def write_report(self, state):
        writes = state.globals.get("dfu_writes", ())
        if not writes:
            return []
        merged = []
        for addr, length in sorted(set(writes)):
            if merged and addr <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], addr + length)
            else:
                merged.append([addr, addr + length])
        rows = []
        for start, end in merged[:MAX_WRITE_RANGES]:
            row = {"address": "%#x" % start, "size": end - start}
            reported = self.data_report(state, start, end - start)
            row.update(reported[0] if isinstance(reported, tuple) else reported)
            if end - start in (1, 2, 4, 8) and "hex" in row:
                try:
                    bv = state.memory.load(start, end - start, endness=self.arch.memory_endness,
                                           inspect=False, disable_actions=True)
                    if not bv.symbolic:
                        row["value"] = "%#x" % state.solver.eval(bv)
                except Exception:  # pylint: disable=broad-except
                    pass
            rows.append(row)
        return rows

    def memory_report(self, state):
        rows = []
        for item in self.spec.get("readMemory") or []:
            addr = h(item["addr"])
            length = int(h(item.get("length", 64)))
            row = {"address": "%#x" % addr, "length": length}
            if item.get("name"):
                row["name"] = item["name"]
            reported = self.data_report(state, addr, length)
            row.update(reported[0] if isinstance(reported, tuple) else reported)
            rows.append(row)
        return rows


# -------------------------------------------------------------------------------------------
# Debug sessions: a live state that is stepped, inspected and edited between requests
# -------------------------------------------------------------------------------------------

MAX_PATHS = 64
MAX_DEBUG_WRITES = 2048
STACK_WORDS = 24


class DebugSession:
    """
    One debugging run of a function. It owns its own project, so its hooks can change while the
    session lives without disturbing anything else, and a set of paths: the one being stepped,
    plus every alternative a symbolic branch produced, parked until selected.
    """

    def __init__(self, sid, directory, spec):
        self.sid = sid
        self.image = Image(directory, spec.get("arch"))
        self.project = self.image.project
        self.arch = self.image.arch
        self.call = Call(self.image, spec)
        state = self.call.build_state()
        self.call.install_hooks()
        state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call.on_simprocedure)
        state.inspect.b("mem_write", when=angr.BP_AFTER, action=self.on_write)
        self.ret_addr = self.project.simos.return_deadend
        self.mask = ~1 if self.arch.name.startswith("ARM") else ~0
        self.paths = {0: state}
        self.info = {0: {"status": "paused"}}
        self.current = 0
        self.next_path = 1
        self.executed = 0
        self.breakpoints = set()
        self.blocks = {}
        self.shown = {}          # path -> {register: text}, to mark what the last step changed
        self.last_stop = "start"
        self.pending = None
        self.stack_range = (self.arch.initial_sp - 0x800000, self.arch.initial_sp + PAGE)

    # ---- observation ----

    def on_write(self, state):
        a = attrs(state)
        addr = a.mem_write_address
        if addr is None:
            return
        if hasattr(addr, "symbolic"):
            if addr.symbolic:
                return
            addr = state.solver.eval(addr)
        length = a.mem_write_length
        if hasattr(length, "symbolic"):
            length = None if length.symbolic else state.solver.eval(length)
        if length is None:
            expr = a.mem_write_expr
            length = expr.size() // 8 if hasattr(expr, "size") else 1
        writes = state.globals.get("dbg_writes", ())
        if len(writes) < MAX_DEBUG_WRITES:
            state.globals["dbg_writes"] = writes + ((addr, int(length)),)

    @staticmethod
    def depth(state):
        return state.globals.get("dfu_depth", 0)

    def block_addrs(self, pc):
        addrs = self.blocks.get(pc)
        if addrs is None:
            try:
                addrs = list(self.project.factory.block(pc).instruction_addrs)
            except Exception:  # pylint: disable=broad-except
                addrs = []
            if len(self.blocks) < 20000:
                self.blocks[pc] = addrs
        return addrs

    def is_hook(self, state, pc):
        # A hook that ran in place hands back the same address marked "do not hook again".
        if state.history.jumpkind == "Ijk_NoHook":
            return False
        return self.project.is_hooked(pc) or self.project.is_hooked(pc & self.mask)

    # ---- stepping ----

    def advance(self, kind, count, limit, deadline, run_to=None):
        pid = self.current
        info = self.info[pid]
        if info["status"] != "paused":
            raise SpecError("This path has finished (%s). Select another path or restart the session."
                            % info["status"])
        if kind not in ("into", "over", "out", "continue", "resume"):
            raise SpecError("unknown step kind %r" % kind)
        state = self.paths[pid]
        start_depth = self.depth(state)
        done = 0
        phase = kind
        first = True
        pending = self.pending if self.pending and self.pending["path"] == pid else None
        self.pending = None
        if kind == "resume":
            if pending:
                # Carry on with the step that ran out of time, exactly where it was.
                phase, start_depth, done, count, run_to = (pending["phase"], pending["depth"],
                                                           pending["done"], pending["count"], pending["runTo"])
                first = False
            else:
                phase = "continue"
        else:
            state.globals["dbg_writes"] = ()
        stops = set(self.breakpoints)
        if run_to is not None:
            stops.add(run_to & self.mask)
        executed = 0
        stop = None

        while True:
            try:
                pc = state.addr
            except Exception:  # pylint: disable=broad-except
                info["status"] = "symbolic_jump"
                stop = "symbolic_jump"
                break
            if pc == self.ret_addr:
                info["status"] = "returned"
                stop = "returned"
                break
            if not first and (pc & self.mask) in stops:
                stop = "breakpoint"
                break
            if executed >= limit:
                stop = "max_steps"
                break
            if time.time() >= deadline:
                stop = "timeout"
                break

            hooked = self.is_hook(state, pc)
            single = phase in ("into", "over")
            if hooked:
                size = None
                ran = 1
            elif single:
                size = 1
                ran = 1
            else:
                addrs = self.block_addrs(pc)
                size = None
                ran = max(1, len(addrs))
                for i, addr in enumerate(addrs[1:], 1):
                    if (addr & self.mask) in stops:
                        size = ran = i  # stop on the breakpoint inside this block
                        break
            try:
                successors = self.successors(state, size)
            except Exception as exc:  # pylint: disable=broad-except
                if size is None and not hooked:
                    # Find the instruction that failed rather than report the block it was in.
                    state, more = self.replay_to_fault(state)
                    executed += more
                info["status"] = "fault"
                info["fault"] = self.call.fault_report(exc)
                stop = "fault"
                break
            executed += ran
            flat = list(successors.flat_successors)
            if not flat:
                if successors.unconstrained_successors:
                    info["status"] = "symbolic_jump"
                    stop = "symbolic_jump"
                else:
                    info["status"] = "exited"
                    stop = "exited"
                break
            self.call.note_transfers(flat)
            state = flat[0]
            first = False
            if len(flat) > 1:
                # A branch on an unknown value: stay on one side, park the others, and stop so
                # whoever is driving decides which to follow.
                info["guard"] = self.guard_text(flat[0])
                for other in flat[1:]:
                    if len(self.paths) >= MAX_PATHS:
                        self.call.warnings.append("More than %d paths; further forks were dropped." % MAX_PATHS)
                        break
                    new_id = self.next_path
                    self.next_path += 1
                    other.globals["dbg_writes"] = ()
                    self.paths[new_id] = other
                    self.info[new_id] = {"status": "paused", "forkedAt": "%#x" % pc,
                                         "guard": self.guard_text(other), "parent": pid}
                info["forkedAt"] = "%#x" % pc
                stop = "fork"
                break

            if phase == "into":
                done += 1
                if done >= count:
                    stop = "step"
                    break
            elif phase == "over":
                if self.depth(state) > start_depth:
                    phase = "finish_over"  # entered a call: run until it comes back
                else:
                    done += 1
                    if done >= count:
                        stop = "step"
                        break
            elif phase == "finish_over":
                if self.depth(state) <= start_depth:
                    done += 1
                    if done >= count:
                        stop = "step"
                        break
                    phase = "over"
            elif phase == "out":
                if self.depth(state) < start_depth:
                    stop = "step"
                    break

        if stop == "timeout":
            self.pending = {"path": pid, "phase": phase, "depth": start_depth, "done": done,
                            "count": count, "runTo": run_to}
        self.paths[pid] = state
        self.executed += executed
        self.last_stop = stop
        return stop

    def successors(self, state, size):
        if size is None:
            return self.project.factory.successors(state)
        return self.project.factory.successors(state, num_inst=size)

    def replay_to_fault(self, state):
        ran = 0
        for _ in range(512):
            try:
                successors = self.project.factory.successors(state, num_inst=1)
            except Exception:  # pylint: disable=broad-except
                break
            flat = successors.flat_successors
            if len(flat) != 1:
                break
            state = flat[0]
            ran += 1
        return state, ran

    @staticmethod
    def guard_text(state):
        try:
            return DebugSession.expr_text(state.history.jump_guard, 160)
        except Exception:  # pylint: disable=broad-except
            return None

    # ---- rendering ----

    @staticmethod
    def expr_text(expr, limit=96):
        text = re.sub(r"^<(BV\d+|Bool) ", "", str(expr))
        if text.endswith(">"):
            text = text[:-1]
        return text if len(text) <= limit else text[:limit - 3] + "..."

    def show(self, state, bv):
        """A value for display: concrete, or symbolic with what it is and a value it can take."""
        if not bv.symbolic:
            return {"value": "%#x" % state.solver.eval(bv)}
        out = {"symbolic": self.expr_text(bv)}
        try:
            values = state.solver.eval_upto(bv, 2)
            if len(values) == 1:
                out["value"] = "%#x" % values[0]
                out["pinned"] = True  # symbolic expression, but only one value satisfies the path
            elif values:
                out["example"] = "%#x" % values[0]
        except Exception as exc:  # pylint: disable=broad-except
            out["error"] = str(exc)
        return out

    def register_names(self):
        names = []
        arch = self.arch
        for offset in (arch.ip_offset, arch.sp_offset):
            name = arch.register_names.get(offset)
            if name and name not in names:
                names.append(name)
        for reg in arch.register_list:
            if getattr(reg, "general_purpose", False) and reg.name not in names:
                names.append(reg.name)
        return names

    def symbol_table(self, state, used=None):
        """
        The unknowns of a path, by the name used to concretize them: the inputs made symbolic,
        the values unmodelled calls returned, and imported variables.

        :param used: when given, imported variables are listed only if their name is in it -
                     that is, once something on the path depends on them. None lists them all.
        """
        table = {}
        for name, bv, _kind in self.call.symbols:
            table[name] = bv
        for _origin, bv in state.globals.get("dfu_assumed", ()):
            for name in bv.variables:
                table.setdefault(name, bv)
        for name, bv in self.call.external_symbols.items():
            if used is None or name in used:
                table.setdefault(name, bv)
        return table

    def snapshot(self, reads=None):
        pid = self.current
        state = self.paths[pid]
        info = self.info[pid]
        call = self.call
        call.state = state
        out = {"session": self.sid, "status": info["status"], "stop": self.last_stop, "path": pid,
               "instructions": self.executed, "depth": self.depth(state)}
        try:
            out["pc"] = "%#x" % state.addr
        except Exception:  # pylint: disable=broad-except
            out["pc"] = None

        previous = self.shown.get(pid, {})
        current = {}
        registers = []
        used = set()  # every unknown a register or a branch taken depends on
        for constraint in state.solver.constraints:
            used |= constraint.variables
        for name in self.register_names():
            try:
                value = state.registers.load(name)
                used |= value.variables
                row = self.show(state, value)
            except Exception:  # pylint: disable=broad-except
                continue
            row["name"] = name
            if "value" in row:
                preview = call.string_at(state, int(row["value"], 16), min_in_image=4)
                if preview is not None:
                    row["string"] = preview
            text = row.get("value") or row.get("symbolic")
            current[name] = text
            if name in previous and previous[name] != text:
                row["changed"] = True
            registers.append(row)
        self.shown[pid] = current
        out["registers"] = registers
        flags = self.flags(state)
        if flags:
            out["flags"] = flags

        out["stack"] = self.stack(state)
        writes = self.writes(state)
        if writes:
            out["writes"] = writes

        log = state.globals.get("dfu_log", ())
        if log:
            out["calls"] = list(log)
        for fd, key in ((1, "stdout"), (2, "stderr")):
            try:
                data = state.posix.dumps(fd)
            except Exception:  # pylint: disable=broad-except
                data = b""
            if data:
                out[key] = text_of(data[-16384:]) if printable(data) else {"hex": data[-MAX_DUMP:].hex()}

        symbols = []
        for name, bv in list(self.symbol_table(state, used).items())[:64]:
            row = self.show(state, bv)
            row["name"] = name
            row["bits"] = bv.size()
            symbols.append(row)
        if symbols:
            out["symbols"] = symbols
        out["constraints"] = len(state.solver.constraints)

        if len(self.paths) > 1:
            rows = []
            for other in sorted(self.paths):
                meta = self.info[other]
                row = {"id": other, "status": meta["status"], "current": other == pid}
                try:
                    row["pc"] = "%#x" % self.paths[other].addr
                except Exception:  # pylint: disable=broad-except
                    row["pc"] = None
                for key in ("guard", "forkedAt", "parent"):
                    if meta.get(key) is not None:
                        row[key] = meta[key]
                rows.append(row)
            out["paths"] = rows

        if info["status"] == "returned":
            loc = call.spec.get("ret")
            if loc and "reg" in loc:
                value = call.value_report(state, call.return_bv(state, loc))
                if loc.get("type"):
                    value["type"] = loc["type"]
                out["returnValue"] = value
        if info.get("fault"):
            out["fault"] = info["fault"]

        buffers = call.buffer_report(state)
        if buffers:
            out["buffers"] = buffers
        if reads:
            saved = call.spec.get("readMemory")
            call.spec["readMemory"] = reads
            try:
                out["memory"] = call.memory_report(state)
            finally:
                call.spec["readMemory"] = saved
        if call.unmodelled_called:
            out["unmodelledExternals"] = sorted(call.unmodelled_called)
        if call.python_hooks:
            out["pythonHooks"] = call.python_hooks
        if call.warnings:
            out["warnings"] = call.warnings
        return out

    def flags(self, state):
        if self.arch.name not in ("AMD64", "X86"):
            return None
        try:
            value = state.regs.rflags if self.arch.name == "AMD64" else state.regs.eflags
            if value.symbolic:
                return "<symbolic>"
            number = state.solver.eval(value)
        except Exception:  # pylint: disable=broad-except
            return None
        names = ((0, "CF"), (2, "PF"), (6, "ZF"), (7, "SF"), (10, "DF"), (11, "OF"))
        return " ".join(name for bit, name in names if number >> bit & 1) or "-"

    def stack(self, state):
        sp = state.regs.sp
        if sp.symbolic:
            return {"sp": "<symbolic>", "words": []}
        base = state.solver.eval(sp)
        size = self.arch.bytes
        words = []
        for i in range(STACK_WORDS):
            addr = base + i * size
            try:
                bv = state.memory.load(addr, size, endness=self.arch.memory_endness,
                                       inspect=False, disable_actions=True)
            except Exception:  # pylint: disable=broad-except
                break
            row = self.show(state, bv)
            row["address"] = "%#x" % addr
            row["offset"] = i * size
            if "value" in row:
                text = self.call.string_at(state, int(row["value"], 16), min_in_image=4)
                if text is not None:
                    row["string"] = text
            words.append(row)
        return {"sp": "%#x" % base, "words": words}

    def writes(self, state):
        """Memory the last step or run changed, merged into ranges."""
        raw = state.globals.get("dbg_writes", ())
        if not raw:
            return []
        merged = []
        for addr, length in sorted(set(raw)):
            if merged and addr <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], addr + length)
            else:
                merged.append([addr, addr + length])
        rows = []
        for start, end in merged[:64]:
            size = end - start
            if self.image.in_image(start):
                region = "program"
            elif self.stack_range[0] <= start < self.stack_range[1]:
                region = "stack"
            else:
                region = "heap"
            row = {"address": "%#x" % start, "size": size, "region": region}
            reported = self.call.data_report(state, start, min(size, 64))
            row.update(reported[0] if isinstance(reported, tuple) else reported)
            rows.append(row)
        if len(merged) > 64:
            rows.append({"omitted": len(merged) - 64})
        return rows

    # ---- editing ----

    def target(self, state, spec):
        """What an edit applies to: (kind, where, current value)."""
        if spec.get("register"):
            name = self.call.register_name(str(spec["register"]))
            return "reg", name, state.registers.load(name)
        if spec.get("address") is not None:
            addr = h(spec["address"])
            size = int(h(spec.get("size") or self.arch.bytes))
            if size < 1 or size > 4096:
                raise SpecError("size must be between 1 and 4096 bytes")
            return "mem", (addr, size), state.memory.load(addr, size, endness=self.arch.memory_endness)
        if spec.get("symbol"):
            table = self.symbol_table(state)
            name = str(spec["symbol"])
            if name not in table:
                raise SpecError("no symbol named %r on this path. Known: %s"
                                % (name, ", ".join(sorted(table)) or "none"))
            bv = table[name]
            if name not in bv.variables or len(bv.variables) != 1 or bv.op != "BVS":
                # the recorded value may be a wider expression; pick out the named leaf
                for leaf in bv.leaf_asts():
                    if leaf.op == "BVS" and name in leaf.variables:
                        bv = leaf
                        break
            return "sym", name, bv
        raise SpecError("say what to act on: 'register', 'address' (+ 'size'), or 'symbol'")

    def store(self, state, kind, where, value):
        if kind == "reg":
            state.registers.store(where, value)
        elif kind == "mem":
            state.memory.store(where[0], value, endness=self.arch.memory_endness)

    def edit(self, request):
        action = request.get("action")
        if action == "select":
            pid = int(h(request.get("path")))
            if pid not in self.paths:
                raise SpecError("no path %d; paths are %s" % (pid, sorted(self.paths)))
            self.current = pid
            self.last_stop = "selected"
            return
        if action == "drop":
            pid = int(h(request.get("path")))
            if pid not in self.paths:
                raise SpecError("no path %d" % pid)
            if len(self.paths) == 1:
                raise SpecError("the last path cannot be dropped; stop the session instead")
            del self.paths[pid]
            del self.info[pid]
            self.shown.pop(pid, None)
            if self.current == pid:
                self.current = sorted(self.paths)[0]
            return

        state = self.paths[self.current]
        self.call.state = state
        if action == "concretize":
            if request.get("all"):
                # One consistent model for everything: fix each unknown in turn.
                for _name, bv in self.symbol_table(state).items():
                    state.add_constraints(bv == state.solver.eval(bv))
                return
            kind, where, bv = self.target(state, request)
            if not bv.symbolic and request.get("value") is None:
                return
            if request.get("value") is None:
                number = state.solver.eval(bv)
            else:
                number = h(request["value"]) & ((1 << bv.size()) - 1)
            condition = bv == number
            if bv.symbolic:
                if not state.solver.satisfiable(extra_constraints=[condition]):
                    raise SpecError("It cannot be %#x on this path: that contradicts the conditions "
                                    "already taken to get here." % number)
                state.add_constraints(condition)
            elif state.solver.eval(bv) != number:
                raise SpecError("It is already concrete (%#x). Use 'set' to overwrite a value."
                                % state.solver.eval(bv))
            # The constraint fixes the symbol; writing the number back makes what holds it concrete.
            self.store(state, kind, where, claripy.BVV(number, bv.size()))
        elif action == "symbolize":
            kind, where, bv = self.target(state, request)
            if kind == "sym":
                raise SpecError("a symbol is already symbolic; name a register or an address")
            label = str(request.get("name") or (where if kind == "reg" else "mem_%x" % where[0]))
            label = re.sub(r"[^A-Za-z0-9_]", "_", label)
            if label in self.symbol_table(state):
                value = fresh_symbol(state, label, bv.size(), label)
            else:
                value = claripy.BVS(label, bv.size(), explicit_name=True)
                state.globals["dfu_assumed"] = state.globals.get("dfu_assumed", ()) + ((label, value),)
            self.store(state, kind, where, value)
        elif action == "set":
            kind, where, bv = self.target(state, request)
            if kind == "sym":
                raise SpecError("use 'concretize' to give a symbol a value")
            if request.get("value") is None:
                raise SpecError("'set' needs a value")
            value = self.call.scalar(request["value"], bv.size(), "value")
            self.store(state, kind, where, Call.fit(value, bv.size()))
        else:
            raise SpecError("unknown edit action %r" % action)

    def rehook(self, spec):
        """Swap the hook configuration of a running session; state is untouched."""
        self.call.remove_hooks()
        for key in ("externalStubs", "stubs", "pyHooks", "unmodelled"):
            if key in spec:
                self.call.spec[key] = spec[key]
        self.call.unmodelled = set()
        self.call.install_hooks()


_SESSIONS = {}
_SESSION_IDS = itertools.count(1)


def session_of(request):
    session = _SESSIONS.get(request.get("session"))
    if session is None:
        raise SpecError("no such debug session (it was closed, or its worker was restarted)")
    return session


def handle_debug(op, request):
    if op == "dbg_open":
        sid = next(_SESSION_IDS)
        session = DebugSession(sid, request["imageDir"], request["spec"])
        _SESSIONS[sid] = session
        return session.snapshot(request.get("readMemory"))
    session = session_of(request)
    if op == "dbg_close":
        session.call.remove_hooks()
        _SESSIONS.pop(session.sid, None)
        return {"closed": True}
    if op == "dbg_step":
        if "breakpoints" in request:
            session.breakpoints = {h(a) & session.mask for a in request["breakpoints"] or []}
        deadline = time.time() + int(request.get("timeoutMs") or 2000) / 1000.0
        run_to = h(request["runTo"]) if request.get("runTo") is not None else None
        session.advance(request.get("kind", "into"), max(1, int(request.get("count") or 1)),
                        int(request.get("maxSteps") or 1000000), deadline, run_to)
    elif op == "dbg_edit":
        session.edit(request)
    elif op == "dbg_hooks":
        session.rehook(request.get("spec") or {})
    elif op != "dbg_state":
        raise SpecError("unknown op %r" % op)
    return session.snapshot(request.get("readMemory"))


def describe_imports(image):
    """How each import would be handled with no stubs or hooks in play."""
    rows = []
    for ext in image.externals:
        cls = find_simprocedure(ext["name"])
        rows.append({"name": ext["name"], "library": ext.get("library"),
                     "model": cls.__name__ if cls is not None else None})
    return rows


# -------------------------------------------------------------------------------------------
# Request loop
# -------------------------------------------------------------------------------------------

_IMAGES = {}
_IMAGE_ORDER = []
MAX_IMAGES = 3


def get_image(key, directory, arch_override):
    cache_key = (key, arch_override or "")
    image = _IMAGES.get(cache_key)
    if image is None:
        image = Image(directory, arch_override)
        _IMAGES[cache_key] = image
        _IMAGE_ORDER.append(cache_key)
        while len(_IMAGE_ORDER) > MAX_IMAGES:
            _IMAGES.pop(_IMAGE_ORDER.pop(0), None)
    return image


def handle(request):
    op = request.get("op")
    if op == "ping":
        return {"pong": True}
    if op == "drop":
        for cache_key in [k for k in _IMAGES if k[0] == request.get("imageKey")]:
            _IMAGES.pop(cache_key, None)
            _IMAGE_ORDER.remove(cache_key)
        return {"dropped": True}
    if op == "check_hook":
        hook = CompiledHook(request.get("name") or "hook", request.get("code") or "")
        return {"ok": True, "parameters": hook.nargs, "varargs": hook.varargs}
    if op == "imports":
        return {"imports": describe_imports(get_image(request["imageKey"], request["imageDir"],
                                                      request.get("arch")))}
    if isinstance(op, str) and op.startswith("dbg_"):
        return handle_debug(op, request)
    if op == "call":
        spec = request["spec"]
        loaded = (request["imageKey"], spec.get("arch") or "") in _IMAGES
        started = time.time()
        image = get_image(request["imageKey"], request["imageDir"], spec.get("arch"))
        result = Call(image, spec).run()
        if not loaded:
            result["imageLoadMs"] = int((time.time() - started) * 1000) - result.get("elapsedMs", 0)
        return result
    raise SpecError("unknown op %r" % op)


def main():
    emit({"ready": True, "protocol": PROTOCOL_VERSION, "angr": getattr(angr, "__version__", "?"),
          "python": sys.version.split()[0], "executable": sys.executable, "pid": os.getpid()})
    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline()
        if not line:
            return  # the parent went away
        line = line.strip()
        if not line:
            continue
        request_id = None
        try:
            request = json.loads(line.decode("utf-8"))
            request_id = request.get("id")
            if request.get("op") == "shutdown":
                emit({"id": request_id, "ok": True, "result": {"bye": True}})
                return
            emit({"id": request_id, "ok": True, "result": handle(request)})
        except SpecError as exc:
            emit({"id": request_id, "ok": False, "kind": "spec", "error": str(exc)})
        except Exception as exc:  # pylint: disable=broad-except
            emit({"id": request_id, "ok": False, "kind": "internal",
                  "error": "%s: %s" % (type(exc).__name__, exc),
                  "traceback": traceback.format_exc(limit=12)})


if __name__ == "__main__":
    main()
