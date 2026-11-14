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
  {"id": n, "op": "drop", "imageKey": "..."}
  {"id": n, "op": "shutdown"}
"""
from __future__ import annotations

import bisect
import json
import logging
import os
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
            value = claripy.BVS("ret_" + str(self.display_name), bits)
            assumed = self.state.globals.get("dfu_assumed", ())
            if len(assumed) < MAX_LOG_ENTRIES:
                self.state.globals["dfu_assumed"] = assumed + ((str(self.display_name), value),)
            return value
        return claripy.BVV(0, bits)


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
        symbolic_default = self.symbolic_run
        for ext in self.image.externals:
            name = ext["name"]
            addrs = [h(a) for a in ext.get("addrs", [])]
            if name in self.image.synthetic:
                addrs.append(self.image.synthetic[name])
            if not addrs:
                continue
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
        for addr in self.hook_names:
            try:
                self.project.unhook(addr)
            except Exception:  # pylint: disable=broad-except
                pass

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

    def string_at(self, state, addr):
        """A printable C string at addr, for annotating pointers in traces and results."""
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
        if isinstance(proc, ExternalStub):
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
                    rows.append({"call": name, "returns": "%#x" % state.solver.eval(bv)})
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
