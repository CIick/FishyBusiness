import asyncio
import signal
import sys
import ctypes
from ctypes import wintypes
import struct
from time import time
from dataclasses import dataclass
from typing import Union, List, Optional

from wizwalker import ClientHandler, Client, Keycode
from wizwalker.memory import MemoryReader, Window
from wizwalker.memory.memory_objects.fish import Fish, FishStatusCode
from loguru import logger
from memobj.process import WindowsProcess

IS_CHEST = False
SCHOOL = "Any"
RANK = 0
ID = 0
SIZE_MIN = 0
SIZE_MAX = 999

SKIP_CAUGHT_FISH_POPUP = True

SPEEDHACK_ENABLED = False
SPEEDHACK_SPEED = 1

SLEEP_POLL_INTERVAL = 0.005
SLEEP_AFTER_CLICK = 0.01
SLEEP_RETRY_DELAY = 0.01
SLEEP_WINDOW_WAIT = 0.02
SLEEP_GAME_STATE = 0.05

PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
INFINITE = 0xFFFFFFFF

kernel32 = ctypes.windll.kernel32

kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetExitCodeThread.restype = wintypes.BOOL
kernel32.VirtualProtectEx.restype = wintypes.BOOL
kernel32.FlushInstructionCache.restype = wintypes.BOOL


@dataclass
class PureSpeedhackOffsets:
    SPEED_MULTIPLIER: int = 0x00
    BASE_TICK_COUNT: int = 0x04
    BASE_TICK_COUNT64: int = 0x08
    BASE_QPC: int = 0x10
    BASE_TIMEGETTIME: int = 0x18
    HOOKS_INSTALLED: int = 0x1C
    ORIGINAL_QPC_IMPL: int = 0x20
    ORIGINAL_TIMEGETTIME_IMPL: int = 0x28
    ORIGINAL_GETTICKCOUNT_BYTES: int = 0x30
    ORIGINAL_GETTICKCOUNT64_BYTES: int = 0x40
    ORIGINAL_QPC_BYTES: int = 0x50
    ORIGINAL_TIMEGETTIME_BYTES: int = 0x60
    HOOK_GETTICKCOUNT: int = 0x100
    HOOK_GETTICKCOUNT64: int = 0x180
    HOOK_QPC: int = 0x200
    HOOK_TIMEGETTIME: int = 0x300
    TRAMPOLINE_QPC: int = 0x400
    TRAMPOLINE_TIMEGETTIME: int = 0x440
    TOTAL_SIZE: int = 0x500


class Speedhack:
    KUSER_SHARED_DATA = 0x7FFE0000
    TICK_COUNT_LOW = 0x7FFE0004
    TICK_COUNT_MULTIPLIER = 0x7FFE0320

    def __init__(self, client: Client):
        self.client = client
        self._process: Optional[WindowsProcess] = None
        self._mem_base: Optional[int] = None
        self._attached = False
        self._current_speed: float = 1.0
        self._gettickcount_addr: Optional[int] = None
        self._gettickcount64_addr: Optional[int] = None
        self._qpc_addr: Optional[int] = None
        self._qpc_ptr_addr: Optional[int] = None
        self._timegettime_addr: Optional[int] = None
        self._timegettime_ptr_addr: Optional[int] = None

    def _get_process(self) -> WindowsProcess:
        if self._process is None:
            pid = self.client._pymem.process_id
            self._process = WindowsProcess.from_id(pid)
        return self._process

    def _resolve_function_addresses(self) -> None:
        process = self._get_process()

        try:
            kernel32_mod = process.get_module_named("KERNEL32.DLL")
        except:
            kernel32_mod = process.get_module_named("kernel32.dll")

        try:
            winmm_mod = process.get_module_named("WINMM.dll")
        except:
            winmm_mod = process.get_module_named("winmm.dll")

        self._gettickcount_addr = kernel32_mod.get_symbol_with_name("GetTickCount")
        self._gettickcount64_addr = kernel32_mod.get_symbol_with_name("GetTickCount64")
        self._qpc_addr = kernel32_mod.get_symbol_with_name("QueryPerformanceCounter")
        self._timegettime_addr = winmm_mod.get_symbol_with_name("timeGetTime")

        qpc_bytes = process.read_memory(self._qpc_addr, 7)
        if qpc_bytes[0:3] == b'\x48\xFF\x25':
            rip_offset = struct.unpack('<i', qpc_bytes[3:7])[0]
            self._qpc_ptr_addr = self._qpc_addr + 7 + rip_offset
        else:
            raise RuntimeError(f"Unexpected QPC prologue: {qpc_bytes.hex()}")

        tgt_bytes = process.read_memory(self._timegettime_addr, 7)
        if tgt_bytes[0:3] == b'\x48\xFF\x25':
            rip_offset = struct.unpack('<i', tgt_bytes[3:7])[0]
            self._timegettime_ptr_addr = self._timegettime_addr + 7 + rip_offset
        else:
            raise RuntimeError(f"Unexpected timeGetTime prologue: {tgt_bytes.hex()}")

        logger.debug(f"GetTickCount: 0x{self._gettickcount_addr:X}")
        logger.debug(f"GetTickCount64: 0x{self._gettickcount64_addr:X}")
        logger.debug(f"QPC: 0x{self._qpc_addr:X} -> ptr at 0x{self._qpc_ptr_addr:X}")
        logger.debug(f"timeGetTime: 0x{self._timegettime_addr:X} -> ptr at 0x{self._timegettime_ptr_addr:X}")

    def _allocate_memory_block(self) -> None:
        process = self._get_process()
        self._mem_base = int(process.allocate_memory(PureSpeedhackOffsets.TOTAL_SIZE))
        logger.debug(f"Allocated speedhack memory at 0x{self._mem_base:X}")

        process.write_memory(
            self._mem_base + PureSpeedhackOffsets.SPEED_MULTIPLIER,
            struct.pack('<f', 1.0)
        )

    def _addr(self, offset: int) -> int:
        return self._mem_base + offset

    def _create_gettickcount_hook(self) -> bytes:
        code = bytearray()
        code += b'\x53'
        code += b'\x51'
        code += b'\x52'
        code += b'\x48\x83\xEC\x20'
        code += b'\xB9\x20\x03\xFE\x7F'
        code += b'\x48\x8B\x09'
        code += b'\x8B\x04\x25\x04\x00\xFE\x7F'
        code += b'\x48\x0F\xAF\xC1'
        code += b'\x48\xC1\xE8\x18'
        code += b'\x48\xBB'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.BASE_TICK_COUNT))
        code += b'\x8B\x1B'
        code += b'\x89\xC1'
        code += b'\x29\xD9'
        code += b'\xF3\x0F\x2A\xC1'
        code += b'\x48\xB8'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.SPEED_MULTIPLIER))
        code += b'\xF3\x0F\x59\x00'
        code += b'\xF3\x0F\x2A\xCB'
        code += b'\xF3\x0F\x58\xC1'
        code += b'\xF3\x0F\x2C\xC0'
        code += b'\x48\x83\xC4\x20'
        code += b'\x5A'
        code += b'\x59'
        code += b'\x5B'
        code += b'\xC3'
        return bytes(code)

    def _create_gettickcount64_hook(self) -> bytes:
        code = bytearray()
        code += b'\x53'
        code += b'\x51'
        code += b'\x52'
        code += b'\x48\x83\xEC\x20'
        code += b'\x8B\x0C\x25\x04\x00\xFE\x7F'
        code += b'\xB8\x20\x03\xFE\x7F'
        code += b'\x48\xC1\xE1\x20'
        code += b'\x48\x8B\x00'
        code += b'\x48\xC1\xE0\x08'
        code += b'\x48\xF7\xE1'
        code += b'\x48\x89\xD0'
        code += b'\x48\xBB'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.BASE_TICK_COUNT64))
        code += b'\x48\x8B\x1B'
        code += b'\x48\x89\xC1'
        code += b'\x48\x29\xD9'
        code += b'\xF2\x48\x0F\x2A\xC1'
        code += b'\x48\xB8'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.SPEED_MULTIPLIER))
        code += b'\xF3\x0F\x10\x08'
        code += b'\xF3\x0F\x5A\xC9'
        code += b'\xF2\x0F\x59\xC1'
        code += b'\xF2\x48\x0F\x2A\xCB'
        code += b'\xF2\x0F\x58\xC1'
        code += b'\xF2\x48\x0F\x2C\xC0'
        code += b'\x48\x83\xC4\x20'
        code += b'\x5A'
        code += b'\x59'
        code += b'\x5B'
        code += b'\xC3'
        return bytes(code)

    def _create_qpc_hook(self) -> bytes:
        code = bytearray()
        code += b'\x53'
        code += b'\x56'
        code += b'\x57'
        code += b'\x48\x83\xEC\x30'
        code += b'\x48\x89\xCE'
        code += b'\x48\xB8'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.TRAMPOLINE_QPC))
        code += b'\xFF\xD0'
        code += b'\x48\x8B\x3E'
        code += b'\x48\xBB'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.BASE_QPC))
        code += b'\x48\x8B\x1B'
        code += b'\x48\x89\xF9'
        code += b'\x48\x29\xD9'
        code += b'\xF2\x48\x0F\x2A\xC1'
        code += b'\x48\xB8'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.SPEED_MULTIPLIER))
        code += b'\xF3\x0F\x10\x08'
        code += b'\xF3\x0F\x5A\xC9'
        code += b'\xF2\x0F\x59\xC1'
        code += b'\xF2\x48\x0F\x2A\xCB'
        code += b'\xF2\x0F\x58\xC1'
        code += b'\xF2\x48\x0F\x2C\xC0'
        code += b'\x48\x89\x06'
        code += b'\xB8\x01\x00\x00\x00'
        code += b'\x48\x83\xC4\x30'
        code += b'\x5F'
        code += b'\x5E'
        code += b'\x5B'
        code += b'\xC3'
        return bytes(code)

    def _create_qpc_trampoline(self) -> bytes:
        code = bytearray()
        code += b'\x48\xB8'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.ORIGINAL_QPC_IMPL))
        code += b'\x48\x8B\x00'
        code += b'\xFF\xE0'
        return bytes(code)

    def _create_timegettime_hook(self) -> bytes:
        code = bytearray()
        code += b'\x53'
        code += b'\x51'
        code += b'\x48\x83\xEC\x28'
        code += b'\x48\xB8'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.TRAMPOLINE_TIMEGETTIME))
        code += b'\xFF\xD0'
        code += b'\x48\xBB'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.BASE_TIMEGETTIME))
        code += b'\x8B\x1B'
        code += b'\x89\xC1'
        code += b'\x29\xD9'
        code += b'\xF3\x0F\x2A\xC1'
        code += b'\x48\xB8'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.SPEED_MULTIPLIER))
        code += b'\xF3\x0F\x59\x00'
        code += b'\xF3\x0F\x2A\xCB'
        code += b'\xF3\x0F\x58\xC1'
        code += b'\xF3\x0F\x2C\xC0'
        code += b'\x48\x83\xC4\x28'
        code += b'\x59'
        code += b'\x5B'
        code += b'\xC3'
        return bytes(code)

    def _create_timegettime_trampoline(self) -> bytes:
        code = bytearray()
        code += b'\x48\xB8'
        code += struct.pack('<Q', self._addr(PureSpeedhackOffsets.ORIGINAL_TIMEGETTIME_IMPL))
        code += b'\x48\x8B\x00'
        code += b'\xFF\xE0'
        return bytes(code)

    def _create_jmp_to_hook(self, hook_addr: int) -> bytes:
        code = bytearray()
        code += b'\xFF\x25\x00\x00\x00\x00'
        code += struct.pack('<Q', hook_addr)
        return bytes(code)

    def _make_writable(self, addr: int, size: int) -> None:
        process = self._get_process()
        old_protect = ctypes.c_ulong()
        kernel32.VirtualProtectEx(
            ctypes.c_void_p(int(process.process_handle)),
            ctypes.c_void_p(int(addr)),
            size,
            PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect)
        )

    def _flush_cache(self, addr: int, size: int) -> None:
        process = self._get_process()
        kernel32.FlushInstructionCache(
            ctypes.c_void_p(int(process.process_handle)),
            ctypes.c_void_p(int(addr)),
            size
        )

    def _call_function(self, func_addr: int) -> int:
        process = self._get_process()

        thread_handle = kernel32.CreateRemoteThread(
            ctypes.c_void_p(int(process.process_handle)),
            None, 0,
            ctypes.c_void_p(int(func_addr)),
            None, 0, None
        )

        if not thread_handle:
            raise RuntimeError(f"CreateRemoteThread failed")

        try:
            kernel32.WaitForSingleObject(thread_handle, INFINITE)
            exit_code = wintypes.DWORD()
            kernel32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code))
            return exit_code.value
        finally:
            kernel32.CloseHandle(thread_handle)

    def _initialize_base_times(self) -> None:
        process = self._get_process()

        k32 = process.get_module_named("KERNEL32.DLL")
        gtc_addr = k32.get_symbol_with_name("GetTickCount")
        base_tc = self._call_function(gtc_addr)
        process.write_memory(
            self._addr(PureSpeedhackOffsets.BASE_TICK_COUNT),
            struct.pack('<I', base_tc)
        )

        gtc64_addr = k32.get_symbol_with_name("GetTickCount64")
        base_tc64 = self._call_function(gtc64_addr)
        process.write_memory(
            self._addr(PureSpeedhackOffsets.BASE_TICK_COUNT64),
            struct.pack('<Q', base_tc64)
        )

        temp_buf = int(process.allocate_memory(8))
        try:
            qpc_caller = bytearray()
            qpc_caller += b'\x48\xB9'
            qpc_caller += struct.pack('<Q', temp_buf)
            qpc_caller += b'\x48\xB8'
            qpc_caller += struct.pack('<Q', self._qpc_addr)
            qpc_caller += b'\xFF\xE0'

            caller_addr = int(process.allocate_memory(32))
            try:
                process.write_memory(caller_addr, bytes(qpc_caller))
                self._call_function(caller_addr)
                base_qpc = struct.unpack('<Q', process.read_memory(temp_buf, 8))[0]
                process.write_memory(
                    self._addr(PureSpeedhackOffsets.BASE_QPC),
                    struct.pack('<Q', base_qpc)
                )
            finally:
                process.free_memory(caller_addr)
        finally:
            process.free_memory(temp_buf)

        tgt_impl = struct.unpack('<Q', process.read_memory(self._timegettime_ptr_addr, 8))[0]
        base_tgt = self._call_function(tgt_impl)
        process.write_memory(
            self._addr(PureSpeedhackOffsets.BASE_TIMEGETTIME),
            struct.pack('<I', base_tgt)
        )

        logger.debug(f"Base times: TC={base_tc}, TC64={base_tc64}, QPC={base_qpc}, TGT={base_tgt}")

    def attach(self) -> None:
        if self._attached:
            return

        process = self._get_process()

        self._resolve_function_addresses()
        self._allocate_memory_block()

        qpc_impl = struct.unpack('<Q', process.read_memory(self._qpc_ptr_addr, 8))[0]
        process.write_memory(
            self._addr(PureSpeedhackOffsets.ORIGINAL_QPC_IMPL),
            struct.pack('<Q', qpc_impl)
        )

        tgt_impl = struct.unpack('<Q', process.read_memory(self._timegettime_ptr_addr, 8))[0]
        process.write_memory(
            self._addr(PureSpeedhackOffsets.ORIGINAL_TIMEGETTIME_IMPL),
            struct.pack('<Q', tgt_impl)
        )

        self._initialize_base_times()

        process.write_memory(
            self._addr(PureSpeedhackOffsets.TRAMPOLINE_QPC),
            self._create_qpc_trampoline()
        )
        process.write_memory(
            self._addr(PureSpeedhackOffsets.TRAMPOLINE_TIMEGETTIME),
            self._create_timegettime_trampoline()
        )

        process.write_memory(
            self._addr(PureSpeedhackOffsets.HOOK_GETTICKCOUNT),
            self._create_gettickcount_hook()
        )
        process.write_memory(
            self._addr(PureSpeedhackOffsets.HOOK_GETTICKCOUNT64),
            self._create_gettickcount64_hook()
        )
        process.write_memory(
            self._addr(PureSpeedhackOffsets.HOOK_QPC),
            self._create_qpc_hook()
        )
        process.write_memory(
            self._addr(PureSpeedhackOffsets.HOOK_TIMEGETTIME),
            self._create_timegettime_hook()
        )

        orig_gtc = process.read_memory(self._gettickcount_addr, 16)
        process.write_memory(self._addr(PureSpeedhackOffsets.ORIGINAL_GETTICKCOUNT_BYTES), orig_gtc)
        self._make_writable(self._gettickcount_addr, 14)
        process.write_memory(
            self._gettickcount_addr,
            self._create_jmp_to_hook(self._addr(PureSpeedhackOffsets.HOOK_GETTICKCOUNT))
        )
        self._flush_cache(self._gettickcount_addr, 14)

        orig_gtc64 = process.read_memory(self._gettickcount64_addr, 16)
        process.write_memory(self._addr(PureSpeedhackOffsets.ORIGINAL_GETTICKCOUNT64_BYTES), orig_gtc64)
        self._make_writable(self._gettickcount64_addr, 14)
        process.write_memory(
            self._gettickcount64_addr,
            self._create_jmp_to_hook(self._addr(PureSpeedhackOffsets.HOOK_GETTICKCOUNT64))
        )
        self._flush_cache(self._gettickcount64_addr, 14)

        orig_qpc = process.read_memory(self._qpc_addr, 16)
        process.write_memory(self._addr(PureSpeedhackOffsets.ORIGINAL_QPC_BYTES), orig_qpc)
        self._make_writable(self._qpc_addr, 14)
        process.write_memory(
            self._qpc_addr,
            self._create_jmp_to_hook(self._addr(PureSpeedhackOffsets.HOOK_QPC))
        )
        self._flush_cache(self._qpc_addr, 14)

        orig_tgt = process.read_memory(self._timegettime_addr, 16)
        process.write_memory(self._addr(PureSpeedhackOffsets.ORIGINAL_TIMEGETTIME_BYTES), orig_tgt)
        self._make_writable(self._timegettime_addr, 14)
        process.write_memory(
            self._timegettime_addr,
            self._create_jmp_to_hook(self._addr(PureSpeedhackOffsets.HOOK_TIMEGETTIME))
        )
        self._flush_cache(self._timegettime_addr, 14)

        process.write_memory(
            self._addr(PureSpeedhackOffsets.HOOKS_INSTALLED),
            struct.pack('<I', 1)
        )

        self._attached = True
        logger.info(f"[Speedhack] Pure Python hooks installed at 0x{self._mem_base:X}")

    def detach(self) -> None:
        if not self._attached:
            return

        process = self._get_process()

        orig_gtc = process.read_memory(self._addr(PureSpeedhackOffsets.ORIGINAL_GETTICKCOUNT_BYTES), 16)
        self._make_writable(self._gettickcount_addr, 16)
        process.write_memory(self._gettickcount_addr, orig_gtc)
        self._flush_cache(self._gettickcount_addr, 16)

        orig_gtc64 = process.read_memory(self._addr(PureSpeedhackOffsets.ORIGINAL_GETTICKCOUNT64_BYTES), 16)
        self._make_writable(self._gettickcount64_addr, 16)
        process.write_memory(self._gettickcount64_addr, orig_gtc64)
        self._flush_cache(self._gettickcount64_addr, 16)

        orig_qpc = process.read_memory(self._addr(PureSpeedhackOffsets.ORIGINAL_QPC_BYTES), 16)
        self._make_writable(self._qpc_addr, 16)
        process.write_memory(self._qpc_addr, orig_qpc)
        self._flush_cache(self._qpc_addr, 16)

        orig_tgt = process.read_memory(self._addr(PureSpeedhackOffsets.ORIGINAL_TIMEGETTIME_BYTES), 16)
        self._make_writable(self._timegettime_addr, 16)
        process.write_memory(self._timegettime_addr, orig_tgt)
        self._flush_cache(self._timegettime_addr, 16)

        process.write_memory(
            self._addr(PureSpeedhackOffsets.HOOKS_INSTALLED),
            struct.pack('<I', 0)
        )

        self._attached = False
        self._current_speed = 1.0
        logger.info("[Speedhack] Hooks removed")

    def set_speed(self, speed: float) -> None:
        if not self._attached:
            logger.warning("[Speedhack] Cannot set speed - not attached")
            return

        process = self._get_process()
        old_speed = self._current_speed

        tick_mult_addr = struct.unpack('<Q', process.read_memory(0x7FFE0320, 8))[0]
        tick_low = struct.unpack('<I', process.read_memory(0x7FFE0004, 4))[0]
        real_tc = (tick_low * tick_mult_addr) >> 24
        old_base_tc = struct.unpack('<I', process.read_memory(
            self._addr(PureSpeedhackOffsets.BASE_TICK_COUNT), 4))[0]
        new_base_tc = int(old_base_tc + (real_tc - old_base_tc) * old_speed) & 0xFFFFFFFF
        process.write_memory(
            self._addr(PureSpeedhackOffsets.BASE_TICK_COUNT),
            struct.pack('<I', new_base_tc)
        )

        tick_mult = struct.unpack('<Q', process.read_memory(0x7FFE0320, 8))[0]
        real_tc64 = ((tick_low << 32) * (tick_mult << 8)) >> 64
        real_tc64 = real_tc
        old_base_tc64 = struct.unpack('<Q', process.read_memory(
            self._addr(PureSpeedhackOffsets.BASE_TICK_COUNT64), 8))[0]
        new_base_tc64 = int(old_base_tc64 + (real_tc64 - old_base_tc64) * old_speed)
        if new_base_tc64 < 0:
            new_base_tc64 = 0
        process.write_memory(
            self._addr(PureSpeedhackOffsets.BASE_TICK_COUNT64),
            struct.pack('<Q', new_base_tc64)
        )

        temp_buf = int(process.allocate_memory(8))
        try:
            qpc_impl = struct.unpack('<Q', process.read_memory(
                self._addr(PureSpeedhackOffsets.ORIGINAL_QPC_IMPL), 8))[0]

            qpc_caller = bytearray()
            qpc_caller += b'\x48\xB9'
            qpc_caller += struct.pack('<Q', temp_buf)
            qpc_caller += b'\x48\xB8'
            qpc_caller += struct.pack('<Q', qpc_impl)
            qpc_caller += b'\xFF\xE0'

            caller_addr = int(process.allocate_memory(32))
            try:
                process.write_memory(caller_addr, bytes(qpc_caller))
                self._call_function(caller_addr)
                real_qpc = struct.unpack('<Q', process.read_memory(temp_buf, 8))[0]
            finally:
                process.free_memory(caller_addr)

            old_base_qpc = struct.unpack('<Q', process.read_memory(
                self._addr(PureSpeedhackOffsets.BASE_QPC), 8))[0]
            new_base_qpc = int(old_base_qpc + (real_qpc - old_base_qpc) * old_speed)
            if new_base_qpc < 0:
                new_base_qpc = 0
            process.write_memory(
                self._addr(PureSpeedhackOffsets.BASE_QPC),
                struct.pack('<Q', new_base_qpc)
            )
        finally:
            process.free_memory(temp_buf)

        tgt_impl = struct.unpack('<Q', process.read_memory(
            self._addr(PureSpeedhackOffsets.ORIGINAL_TIMEGETTIME_IMPL), 8))[0]
        real_tgt = self._call_function(tgt_impl)
        old_base_tgt = struct.unpack('<I', process.read_memory(
            self._addr(PureSpeedhackOffsets.BASE_TIMEGETTIME), 4))[0]
        new_base_tgt = int(old_base_tgt + (real_tgt - old_base_tgt) * old_speed) & 0xFFFFFFFF
        process.write_memory(
            self._addr(PureSpeedhackOffsets.BASE_TIMEGETTIME),
            struct.pack('<I', new_base_tgt)
        )

        process.write_memory(
            self._addr(PureSpeedhackOffsets.SPEED_MULTIPLIER),
            struct.pack('<f', speed)
        )

        self._current_speed = speed
        logger.info(f"[Speedhack] Speed set to {speed}x")

    def get_speed(self) -> float:
        if self._mem_base is None:
            return 1.0
        process = self._get_process()
        data = process.read_memory(self._addr(PureSpeedhackOffsets.SPEED_MULTIPLIER), 4)
        return struct.unpack('<f', data)[0]

    def is_attached(self) -> bool:
        if self._mem_base is None:
            return False
        process = self._get_process()
        data = process.read_memory(self._addr(PureSpeedhackOffsets.HOOKS_INSTALLED), 4)
        return struct.unpack('<I', data)[0] != 0

    def cleanup(self) -> None:
        if self._mem_base and self._process:
            try:
                self._process.free_memory(self._mem_base)
            except:
                pass
            self._mem_base = None

    def __enter__(self):
        self.attach()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.detach()
        self.cleanup()
        return False


_cleanup_state = {
    "client": None,
    "address_bytes": [],
    "handler": None,
    "patches_applied": False,
    "shutdown_requested": False,
    "speedhack": None,
}

def should_exit():
    return _cleanup_state["shutdown_requested"]

async def patch(client:Client) -> List[tuple[int, bytes]]:
    async def readbytes_writebytes(pattern:bytes, write_bytes:bytes, name:str = "", offset: int = 0) -> tuple[int, bytes]:
        add = await reader.pattern_scan(pattern, return_multiple=False, module="WizardGraphicalClient.exe")
        if add is None:
            logger.warning(f"Pattern not found: {name}")
            return None
        add = add + offset
        old_bytes = await reader.read_bytes(add, len(write_bytes))
        await reader.write_bytes(add, write_bytes)
        logger.info(f"Patched {name} at {hex(add)}")
        return (add, old_bytes)

    address_oldbytes = []
    reader = MemoryReader(client._pymem)

    async def fish_distance_check_patch():
        pattern = rb"\x0F\x84....\xF3\x0F\x10\x70\x6C\x0F\x28\xC6"
        write_bytes = b"\x90" * 6
        result = await readbytes_writebytes(pattern, write_bytes, "fish_distance_check")
        if result: address_oldbytes.append(result)

    async def fish_fov_check_patch():
        pattern = rb"\x0F\x84....\x48\x8B\x8B....\x45\x32"
        write_bytes = b"\x90" * 6
        result = await readbytes_writebytes(pattern, write_bytes, "fish_fov_check")
        if result: address_oldbytes.append(result)

    async def fish_distance_threshold_patch():
        pattern = rb"\x0F\x86....\x44\x0F\x2F\x05"
        write_bytes = b"\x90" * 6
        result = await readbytes_writebytes(pattern, write_bytes, "fish_distance_threshold")
        if result: address_oldbytes.append(result)

    async def fish_min_distance_patch():
        pattern = rb"\x0F\x86....\xF3\x41\x0F\x5C\xF2"
        write_bytes = b"\x90" * 6
        result = await readbytes_writebytes(pattern, write_bytes, "fish_min_distance")
        if result: address_oldbytes.append(result)

    async def fish_final_angle_max_patch():
        pattern = rb"\x0F\x82....\xF3\x44\x0F\x10\x0D....\x41\x0F\x2F\xC1"
        write_bytes = b"\x90" * 6
        result = await readbytes_writebytes(pattern, write_bytes, "fish_final_angle_max")
        if result: address_oldbytes.append(result)

    async def fish_final_angle_min_patch():
        pattern = rb"\x0F\x82....\xC7\x83........\x8B\x93"
        write_bytes = b"\x90" * 6
        result = await readbytes_writebytes(pattern, write_bytes, "fish_final_angle_min")
        if result: address_oldbytes.append(result)

    async def scare_fish_patch():
        pattern = rb"\x0F\x2F\xC2\x76.\x41\xB1\x01"
        write_bytes = b"\x0F\x2F\xC2\xEB"
        result = await readbytes_writebytes(pattern, write_bytes, "scare_fish")
        if result: address_oldbytes.append(result)

    async def skip_submersion_animation():
        pattern = rb"\xF3\x0F\x11\x87\xE4\x02\x00\x00\x44\x0F\x2F\xD8\x0F\x82\xE5\x00\x00\x00"
        write_bytes = b"\xF3\x0F\x11\x87\xE4\x02\x00\x00\x44\x0F\x2F\xD8\x31\xF6\x90\x90\x90\x90"
        result = await readbytes_writebytes(pattern, write_bytes, "skip_submersion")
        if result: address_oldbytes.append(result)

    async def instant_fish_state_patch():
        pattern = rb"\x44\x0F\x2F\xC0\x72.\x44\x89\xB3\x08\x01\x00\x00\xC7\x83\xB8\x00\x00\x00\x03"
        write_bytes = b"\x44\x0F\x2F\xC0\x90\x90\x44\x89\xB3\x08\x01\x00\x00\xC7\x83\xB8\x00\x00\x00\x03"
        result = await readbytes_writebytes(pattern, write_bytes, "instant_fish_state")
        if result: address_oldbytes.append(result)

    async def fish_teleport_to_bobber_patch():
        pattern = rb"\xF3\x41\x0F\x58\xE8\x0F\x2F\xEE\x0F\x87"
        write_bytes = b"\xF3\x41\x0F\x58\xE8\x0F\x2F\xEE\x90\x90\x90\x90\x90\x90"
        result = await readbytes_writebytes(pattern, write_bytes, "fish_teleport_to_bobber")
        if result: address_oldbytes.append(result)

    async def sentinel_fish_teleport_patch():
        pattern = rb"\xF3\x0F\x58\xE5\xF3\x41\x0F\x58\xE0\x0F\x2F\xDC\x77"
        write_bytes = b"\xF3\x0F\x58\xE5\xF3\x41\x0F\x58\xE0\x0F\x2F\xDC\x90\x90"
        result = await readbytes_writebytes(pattern, write_bytes, "sentinel_fish_teleport")
        if result: address_oldbytes.append(result)

    async def skip_bobber_flying_animation():
        pattern = rb"\x0F\x2F\x15....\x0F\x86\xCA\x05\x00\x00\xF3\x0F\x10\x8F\x08\x05\x00\x00"
        add = await reader.pattern_scan(pattern, return_multiple=False, module="WizardGraphicalClient.exe")
        if add is None:
            logger.warning("Pattern not found: skip_bobber_flying")
            return
        old_bytes = await reader.read_bytes(add, 18)
        write_bytes = old_bytes[:7] + b"\xE9\xCB\x05\x00\x00\x90" + old_bytes[13:]
        await reader.write_bytes(add, write_bytes)
        logger.info(f"Patched skip_bobber_flying at {hex(add)}")
        address_oldbytes.append((add, old_bytes))

    async def teleport_bobber_to_target():
        pattern = rb"\xF3\x0F\x59\xC6\xF3\x44\x0F\x58\xD0\xF3\x44\x0F\x11\x55\x88\xF3\x44\x0F\x58\xCA\xF3\x44\x0F\x11\x4D\x8C"
        add = await reader.pattern_scan(pattern, return_multiple=False, module="WizardGraphicalClient.exe")
        if add is None:
            logger.warning("Pattern not found: teleport_bobber_to_target")
            return
        old_bytes = await reader.read_bytes(add, 26)
        write_bytes = (old_bytes[:4] +
                      b"\xF3\x44\x0F\x10\x57\x60" +
                      b"\x90\x90\x90\x90\x90" +
                      b"\xF3\x44\x0F\x10\x4F\x64" +
                      b"\x90\x90\x90\x90\x90")
        await reader.write_bytes(add, write_bytes)
        logger.info(f"Patched teleport_bobber_to_target at {hex(add)}")
        address_oldbytes.append((add, old_bytes))

    async def skip_bobber_water_animation():
        pattern = rb"\x49\x8B\x0C\x24\x48\x85\xC9\x0F\x84....\x83\xBF\x00\x02\x00\x00\x00"
        write_bytes = b"\x49\x8B\x0C\x24\x48\x85\xC9\xE9\x14\x01\x00\x00\x90\x83\xBF\x00\x02\x00\x00\x00"
        result = await readbytes_writebytes(pattern, write_bytes, "skip_bobber_water")
        if result: address_oldbytes.append(result)

    async def skip_fish_rotation():
        pattern = rb"\x83\xF9\x05\x0F\x85....\x41\x0F\x28"
        write_bytes = b"\x83\xF9\x05\xE9\x7D\x03\x00\x00\x90\x41\x0F\x28"
        result = await readbytes_writebytes(pattern, write_bytes, "skip_fish_rotation")
        if result: address_oldbytes.append(result)

    async def skip_struggle():
        pattern = rb"\x80\xBF\xF1\x04\x00\x00\x00\x74.\x80\xBF\xF2\x04\x00\x00\x00\x74."
        write_bytes = b"\x80\xBF\xF1\x04\x00\x00\x00\x90\x90\x80\xBF\xF2\x04\x00\x00\x00\x90\x90"
        result = await readbytes_writebytes(pattern, write_bytes, "skip_struggle")
        if result: address_oldbytes.append(result)

    async def skip_approach_delay():
        pattern = rb"\x44\x0F\x2F\xC0\x0F\x82....\x44\x89\xB3\xC8\x00\x00\x00\xC6\x43\x74\x01"
        add = await reader.pattern_scan(pattern, return_multiple=False, module="WizardGraphicalClient.exe")
        if add is None:
            logger.warning("Pattern not found: skip_approach_delay")
            return
        old_bytes = await reader.read_bytes(add, 21)
        write_bytes = old_bytes[:4] + b"\x90\x90\x90\x90\x90\x90" + old_bytes[10:]
        await reader.write_bytes(add, write_bytes)
        logger.info(f"Patched skip_approach_delay at {hex(add)}")
        address_oldbytes.append((add, old_bytes))

    async def skip_chest_animation_phase1():
        pattern = rb"\x83\xF8\x37\x7D\x56"
        write_bytes = b"\x83\xF8\x37\xEB\x56"
        result = await readbytes_writebytes(pattern, write_bytes, "skip_chest_phase1")
        if result: address_oldbytes.append(result)

    async def skip_chest_animation_phase2():
        pattern = rb"\x83\xF8\x6E\x0F\x83\x80\x00\x00\x00"
        write_bytes = b"\x83\xF8\x6E\xE9\x81\x00\x00\x00\x90"
        result = await readbytes_writebytes(pattern, write_bytes, "skip_chest_phase2")
        if result: address_oldbytes.append(result)

    async def skip_chest_animation_phase3():
        pattern = rb"\xF3\x0F\x10\x0D....\x0F\x2F\xC8\x0F\x87\xB5\x00\x00\x00"
        add = await reader.pattern_scan(pattern, return_multiple=False, module="WizardGraphicalClient.exe")
        if add is None:
            logger.warning("Pattern not found: skip_chest_phase3")
            return
        old_bytes = await reader.read_bytes(add, 17)
        write_bytes = old_bytes[:11] + b"\xE9\xB6\x00\x00\x00\x90"
        await reader.write_bytes(add, write_bytes)
        logger.info(f"Patched skip_chest_phase3 at {hex(add)}")
        address_oldbytes.append((add, old_bytes))

    async def skip_fish_animation_phase1():
        pattern = rb"\x83\xF8\x37\x0F\x8D\x8A\x00\x00\x00"
        write_bytes = b"\x83\xF8\x37\xE9\x8B\x00\x00\x00\x90"
        result = await readbytes_writebytes(pattern, write_bytes, "skip_fish_phase1")
        if result: address_oldbytes.append(result)

    async def skip_fish_animation_phase2():
        pattern = rb"\x83\xF8\x6E\x0F\x8D\xBB\x00\x00\x00"
        write_bytes = b"\x83\xF8\x6E\xE9\xBC\x00\x00\x00\x90"
        result = await readbytes_writebytes(pattern, write_bytes, "skip_fish_phase2")
        if result: address_oldbytes.append(result)

    async def skip_fish_animation_phase3():
        pattern = rb"\x0F\x2F\xC8\x0F\x87\xFD\x00\x00\x00"
        write_bytes = b"\x0F\x2F\xC8\xE9\xFE\x00\x00\x00\x90"
        result = await readbytes_writebytes(pattern, write_bytes, "skip_fish_phase3")
        if result: address_oldbytes.append(result)

    async def force_early_fish_init():
        pattern = rb"\x83\x7F\x14\x41\x0F\x8C\x3E\x03\x00\x00"
        write_bytes = b"\x83\x7F\x14\x41\x90\x90\x90\x90\x90\x90"
        result = await readbytes_writebytes(pattern, write_bytes, "force_early_fish_init")
        if result: address_oldbytes.append(result)

    async def skip_casting_animation():
        pattern = rb"\x48\x8B\xCB\xFF\x50\x70\x90\x48\x8B\x55\xF8"
        write = b"\x48\x8B\xCB\x90\x90\x90\x90\x48\x8B\x55\xF8"
        result = await readbytes_writebytes(pattern, write, "skip_casting_animation")
        if result:
            address_oldbytes.append(result)
            return
        logger.warning("skip_casting_animation: Pattern not matched")

    async def skip_summon_animation():
        pattern = rb"\x8B\x54\x24.\x48\x8B\xCF\xE8....\x90\x48\x8B\x5E.\x48\x85\xDB\x74\x2E\xBF....\x8B\xC7\xF0\x0F\xC1\x43.\x83\xF8.\x75\x1D\x48\x8B\x03\x48\x8B\xCB\xFF\x50.\xF0\x0F\xC1\x7B.\x83\xFF.\x75\x0A\x48\x8B\x03\x48\x8B\xCB\xFF\x50.\x90\x48\x8B\x5C\x24.\x48\x8B\x74\x24.\x48\x83\xC4.\x5F\xC3"
        write_bytes = b"\x90" * 5
        result = await readbytes_writebytes(pattern, write_bytes, "skip_summon_animation", offset=7)
        if result: address_oldbytes.append(result)

    async def zero_casting_timer():
        pattern = rb"\x49\x8D\x8E\xD0\x00\x00\x00\x48\x8B\x01\xBA\x14\x05\x00\x00\xFF\x50\x18"
        write_bytes = b"\x49\x8D\x8E\xD0\x00\x00\x00\x48\x8B\x01\xBA\x00\x00\x00\x00\xFF\x50\x18"
        result = await readbytes_writebytes(pattern, write_bytes, "zero_casting_timer")
        if result: address_oldbytes.append(result)

    async def zero_summon_timer():
        pattern = rb"\x48\x8D\x8B....\x48\x8B\x01\xBA\x14\x05\x00\x00\xFF\x50."
        write_bytes = b"\x00\x00\x00\x00"
        result = await readbytes_writebytes(pattern, write_bytes, "zero_summon_timer", offset=11)
        if result: address_oldbytes.append(result)

    async def skip_caught_fish_window():
        pattern = rb"\x0F\x28\xD6.\x8B\xD7\x48\x8B\xCF\xE8....\x90"
        add = await reader.pattern_scan(pattern, return_multiple=False, module="WizardGraphicalClient.exe")
        if add is None:
            logger.warning("Pattern not found: skip_caught_fish_window")
            return
        old_bytes = await reader.read_bytes(add, 15)
        write_bytes = old_bytes[:9] + b"\x90\x90\x90\x90\x90" + old_bytes[14:]
        await reader.write_bytes(add, write_bytes)
        logger.info(f"Patched skip_caught_fish_window at {hex(add)}")
        address_oldbytes.append((add, old_bytes))

    async def bypass_ripple_framerate_limiter():
        pattern = rb"\xF3\x0F\x11\x77\x10\xF3\x0F\x10\x05....\x0F\x2F\xF0\x0F\x86...."
        add = await reader.pattern_scan(pattern, return_multiple=False, module="WizardGraphicalClient.exe")
        if add is None:
            logger.warning("Pattern not found: bypass_ripple_framerate")
            return
        old_bytes = await reader.read_bytes(add, 22)
        write_bytes = old_bytes[:16] + b"\x90\x90\x90\x90\x90\x90"
        await reader.write_bytes(add, write_bytes)
        logger.info(f"Patched bypass_ripple_framerate at {hex(add)}")
        address_oldbytes.append((add, old_bytes))

    async def bypass_splash_framerate_limiter():
        pattern = rb"\xF3\x0F\x11\x4F\x10\xF3\x0F\x10\x05....\x0F\x2F\xC8\x0F\x86...."
        add = await reader.pattern_scan(pattern, return_multiple=False, module="WizardGraphicalClient.exe")
        if add is None:
            logger.warning("Pattern not found: bypass_splash_framerate")
            return
        old_bytes = await reader.read_bytes(add, 22)
        write_bytes = old_bytes[:16] + b"\x90\x90\x90\x90\x90\x90"
        await reader.write_bytes(add, write_bytes)
        logger.info(f"Patched bypass_splash_framerate at {hex(add)}")
        address_oldbytes.append((add, old_bytes))

    patches = [
        fish_distance_check_patch(),
        fish_fov_check_patch(),
        fish_distance_threshold_patch(),
        fish_min_distance_patch(),
        fish_final_angle_max_patch(),
        fish_final_angle_min_patch(),
        scare_fish_patch(),
        skip_submersion_animation(),
        instant_fish_state_patch(),
        fish_teleport_to_bobber_patch(),
        sentinel_fish_teleport_patch(),
        skip_casting_animation(),
        skip_summon_animation(),
        zero_casting_timer(),
        zero_summon_timer(),
        skip_bobber_flying_animation(),
        teleport_bobber_to_target(),
        skip_bobber_water_animation(),
        skip_fish_rotation(),
        skip_struggle(),
        skip_approach_delay(),
        skip_chest_animation_phase1(),
        skip_chest_animation_phase2(),
        skip_chest_animation_phase3(),
        force_early_fish_init(),
        skip_fish_animation_phase1(),
        skip_fish_animation_phase2(),
        skip_fish_animation_phase3(),
        skip_caught_fish_window(),
        bypass_ripple_framerate_limiter(),
        bypass_splash_framerate_limiter(),
    ]

    await asyncio.gather(*patches)

    return address_oldbytes

async def reset_patch(client: Client, address_bytes: List[tuple[int, bytes]]):
    if not address_bytes:
        logger.info("No patches to restore")
        return

    logger.info(f"Restoring {len(address_bytes)} patches...")
    reader = MemoryReader(client._pymem)
    restored_count = 0

    for address, oldbytes in address_bytes:
        try:
            await reader.write_bytes(address, oldbytes)
            restored_count += 1
            logger.debug(f"Restored patch at 0x{address:X} ({len(oldbytes)} bytes)")
        except Exception as e:
            logger.error(f"Failed to restore patch at 0x{address:X}: {e}")

    logger.info(f"Successfully restored {restored_count}/{len(address_bytes)} patches")
    _cleanup_state["patches_applied"] = False

async def window_exists(client, window_name: str, *, check_if_visible=True):
    w = await client.root_window.get_windows_with_name(window_name)
    if check_if_visible:
        return len(w) > 0 and await w[0].is_visible()
    else:
        return len(w) > 0

async def wait_for_window(client, window_name, *, timeout=10, check_if_visible=True):
    start = time()
    while not await window_exists(client, window_name, check_if_visible=check_if_visible) and not should_exit():
        if time() - start >= timeout:
            break
        await asyncio.sleep(SLEEP_POLL_INTERVAL)

async def wait_to_click_window_with_name(client: Client, window_name: str, *, timeout=10, check_if_visible=True):
    await wait_for_window(client, window_name, timeout=timeout, check_if_visible=check_if_visible)
    await asyncio.sleep(SLEEP_AFTER_CLICK)
    async with client.mouse_handler:
        await client.mouse_handler.click_window_with_name(window_name)

async def sell_basket(client: Client):
    if should_exit():
        return
    await client.send_key(Keycode.V)
    while await window_exists(client, "Trash", check_if_visible=True) and not should_exit():
        while not (await window_exists(client, "centerButton")) and not should_exit():
            try:
                async with client.mouse_handler:
                    await client.mouse_handler.click_window_with_name("Trash")
            except ValueError:
                await asyncio.sleep(SLEEP_RETRY_DELAY)

        if should_exit():
            break

        while await window_exists(client, "centerButton") and not should_exit():
            try:
                async with client.mouse_handler:
                    await client.mouse_handler.click_window_with_name("centerButton")
            except ValueError:
                await asyncio.sleep(SLEEP_RETRY_DELAY)

    if not should_exit():
        await client.send_key(Keycode.V)

async def fetch_fish_list(fishing_manager):
    while not should_exit():
        try:
            return await fishing_manager.fish_list()
        except RuntimeError:
            await asyncio.sleep(SLEEP_RETRY_DELAY)
    return []

async def banish_config(fishing_manager):
    kept_fish = []
    for fish in await fetch_fish_list(fishing_manager):
        fish_temp = await fish.template()
        fish_is_accepted = True
        fish_size = await fish.size()
        if (await fish.is_chest()) != IS_CHEST:
            fish_is_accepted = False

        if (SCHOOL != "Any") and (await fish_temp.school_name() != SCHOOL):
            fish_is_accepted = False

        if (RANK != 0) and (await fish_temp.rank() != RANK):
            fish_is_accepted = False

        if (ID != 0) and (await fish.template_id() != ID):
            fish_is_accepted = False

        if fish_size < SIZE_MIN or fish_size > SIZE_MAX:
            fish_is_accepted = False

        if not fish_is_accepted:
            await fish.write_status_code(FishStatusCode.escaped)
        else:
            kept_fish.append(fish)
    return kept_fish

async def refresh_pond(client, fishing_manager):
    if should_exit():
        return
    fish_list = await banish_config(fishing_manager)
    while len(fish_list) == 0 and not should_exit():
        fish_windows = await client.root_window.get_windows_with_name("FishingWindow")
        while len(fish_windows) == 0 and not should_exit():
            async with client.mouse_handler:
                await client.mouse_handler.click_window_with_name("OpenFishingButton")
            fish_windows = await client.root_window.get_windows_with_name("FishingWindow")
            await asyncio.sleep(SLEEP_WINDOW_WAIT)

        if should_exit():
            return

        fish_window: Window = fish_windows[0]
        fish_sub_window = await fish_window.get_child_by_name("FishingSubWindow")
        bottomframe = await fish_sub_window.get_child_by_name("BottomFrame")
        icon2 = await bottomframe.get_child_by_name("Icon2")
        async with client.mouse_handler:
            await client.mouse_handler.click_window(icon2)

        while not should_exit():
            try:
                if len(await fetch_fish_list(fishing_manager)) > 0:
                    break
            except RuntimeError:
                await asyncio.sleep(SLEEP_RETRY_DELAY)

        if should_exit():
            return

        await asyncio.sleep(SLEEP_AFTER_CLICK)
        fish_list = await banish_config(fishing_manager)

async def graceful_shutdown():
    logger.info("Initiating graceful shutdown...")
    _cleanup_state["shutdown_requested"] = True

    client = _cleanup_state["client"]
    address_bytes = _cleanup_state["address_bytes"]
    handler = _cleanup_state["handler"]
    speedhack = _cleanup_state["speedhack"]

    if speedhack:
        try:
            speedhack.detach()
            speedhack.cleanup()
            logger.info("Speedhack detached successfully")
        except Exception as e:
            logger.error(f"Error detaching speedhack during shutdown: {e}")

    if client and _cleanup_state["patches_applied"] and address_bytes:
        try:
            await reset_patch(client, address_bytes)
        except Exception as e:
            logger.error(f"Error restoring patches during shutdown: {e}")

    if handler:
        try:
            await handler.close()
            logger.info("Handler closed successfully")
        except Exception as e:
            logger.error(f"Error closing handler: {e}")

    logger.info("Shutdown complete")


def signal_handler(signum, frame):
    sig_name = signal.Signals(signum).name
    print(f"\n{sig_name} received. Stopping and unhooking patches...")
    _cleanup_state["shutdown_requested"] = True


async def main():
    handler = ClientHandler()
    client = handler.get_new_clients()[0]

    _cleanup_state["handler"] = handler
    _cleanup_state["client"] = client
    _cleanup_state["address_bytes"] = []

    speedhack = None
    try:
        print("Preparing")
        await client.activate_hooks()
        address_bytes = await patch(client)
        _cleanup_state["address_bytes"] = address_bytes
        _cleanup_state["patches_applied"] = True
        logger.info(f"Applied {len(address_bytes)} patches")

        if SPEEDHACK_ENABLED:
            try:
                speedhack = Speedhack(client)
                speedhack.attach()
                speedhack.set_speed(SPEEDHACK_SPEED)
                _cleanup_state["speedhack"] = speedhack
                print(f"Speedhack enabled at {SPEEDHACK_SPEED}x speed")
            except Exception as e:
                logger.error(f"Failed to initialize speedhack: {e}")
                speedhack = None

        print("Ready for Fish")

        fishing_manager = await client.game_client.fishing_manager()
        fish_caught = 0
        total = time()
        while not _cleanup_state["shutdown_requested"]:
            start = time()
            await refresh_pond(client, fishing_manager)
            fish_list = await fetch_fish_list(fishing_manager)

            fish_windows = await client.root_window.get_windows_with_name("FishingWindow")

            while len(fish_windows) == 0 and not should_exit():
                async with client.mouse_handler:
                    await client.mouse_handler.click_window_with_name("OpenFishingButton")
                fish_windows = await client.root_window.get_windows_with_name("FishingWindow")

            if should_exit():
                break

            fish_window: Window = fish_windows[0]
            fish_sub_window = await fish_window.get_child_by_name("FishingSubWindow")
            bottomframe = await fish_sub_window.get_child_by_name("BottomFrame")
            icon1 = await bottomframe.get_child_by_name("Icon1")
            async with client.mouse_handler:
                await client.mouse_handler.click_window(icon1)

            is_hooked = False
            basket_full = False
            while not is_hooked and not should_exit():
                if await window_exists(client, "MessageBoxModalWindow"):
                    await wait_to_click_window_with_name(client, "rightButton")
                    await sell_basket(client)
                    basket_full = False
                    break

                fish_list = await fetch_fish_list(fishing_manager)
                statuses = await asyncio.gather(*[fish.status_code() for fish in fish_list])
                for status in statuses:
                    if status == FishStatusCode.unknown2:
                        is_hooked = True
                        break

            if should_exit():
                break

            if basket_full:
                continue

            await client.send_key(Keycode.SPACEBAR)

            fish_failed = False
            if SKIP_CAUGHT_FISH_POPUP:
                await asyncio.sleep(SLEEP_GAME_STATE)

                try:
                    reader = MemoryReader(client._pymem)

                    async def enable_button(button_name: str):
                        buttons = await client.root_window.get_windows_with_name(button_name)
                        if not buttons:
                            logger.debug(f"Button {button_name} not found")
                            return False

                        btn = buttons[0]
                        btn_addr = None
                        try:
                            btn_addr = await btn.read_base_address()
                        except AttributeError:
                            try:
                                btn_addr = btn.base_address
                            except AttributeError:
                                if hasattr(btn, '_address'):
                                    btn_addr = btn._address

                        if btn_addr is None:
                            logger.warning(f"Could not get address for {button_name}")
                            return False

                        await reader.write_bytes(btn_addr + 0x2B0, b'\x00')
                        logger.debug(f"Enabled {button_name} at {hex(btn_addr)}")
                        return True

                    await enable_button("OpenFishingButton")
                    await enable_button("CloseFishingButton")

                except Exception as e:
                    logger.warning(f"Failed to re-enable fishing buttons: {e}")
                    try:
                        open_buttons = await client.root_window.get_windows_with_name("OpenFishingButton")
                        if open_buttons:
                            async with client.mouse_handler:
                                await client.mouse_handler.click_window(open_buttons[0])
                            logger.info("Fallback: clicked OpenFishingButton")
                    except Exception as e2:
                        logger.error(f"Fallback also failed: {e2}")
            else:
                timeout = time()
                while len(await client.root_window.get_windows_with_name("CaughtFishModalWindow")) == 0 and not should_exit():
                    if time() - timeout >= 10:
                        fish_failed = True
                        break

                if should_exit():
                    break

                if fish_failed:
                    continue

                while len(await client.root_window.get_windows_with_name("CaughtFishModalWindow")) > 0 and not should_exit():
                    caught_window: Window = (await client.root_window.get_windows_with_name("CaughtFishModalWindow"))[0]
                    caught_fish = await caught_window.get_child_by_name("CaughtFish")
                    exit_button = await caught_fish.get_child_by_name("exit")
                    async with client.mouse_handler:
                        await client.mouse_handler.click_window(exit_button)
                    await asyncio.sleep(SLEEP_AFTER_CLICK)

            if should_exit():
                break

            fish_caught += 1

            if fish_caught % 100 == 0 and not IS_CHEST:
                await sell_basket(client)

            total_time = round((time() - total) / 60, 2)
            print(f"Fish Caught: {fish_caught}, Number of fish in pool: {len(fish_list) - 1}, Time: {total_time} minutes, Seconds per fish: {round((total_time / fish_caught) * 60, 2)}")

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        print("\nUnhooking patches and cleaning up...")

        if speedhack:
            try:
                print("Detaching speedhack...")
                speedhack.detach()
                speedhack.cleanup()
            except Exception as e:
                logger.error(f"Error detaching speedhack: {e}")

        if _cleanup_state["patches_applied"] and address_bytes:
            await reset_patch(client, address_bytes)

        print("Closing handler...")
        await handler.close()
        print("Gracefully exited")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete")
    except SystemExit:
        print("\nShutdown complete")
