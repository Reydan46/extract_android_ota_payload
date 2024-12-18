#!/usr/bin/env python

import hashlib
import os
import struct
import subprocess
from pathlib import Path
from zipfile import ZipFile
import update_metadata_pb2
from google.protobuf import message
import argparse
import shutil
import sys
import signal
import lzma
import bz2

BLOCK_SIZE = 4096
BRILLO_MAJOR_PAYLOAD_VERSION = 2


class PayloadError(Exception):
    pass


class Payload:
    class _PayloadHeader:
        _MAGIC = b'CrAU'

        def __init__(self) -> None:
            self.version = None
            self.manifest_len = None
            self.metadata_signature_len = None
            self.size = None

        def read_from_payload(self, payload_file) -> None:
            magic = payload_file.read(4)
            if magic != self._MAGIC:
                raise PayloadError(f'Invalid payload magic: {magic}')
            self.version = struct.unpack('>Q', payload_file.read(8))[0]
            self.manifest_len = struct.unpack('>Q', payload_file.read(8))[0]
            self.size = 20
            self.metadata_signature_len = 0
            if self.version != BRILLO_MAJOR_PAYLOAD_VERSION:
                raise PayloadError(f'Unsupported payload version ({self.version})')
            self.size += 4
            self.metadata_signature_len = struct.unpack('>I', payload_file.read(4))[0]

    def __init__(self, payload_file) -> None:
        self.payload_file = payload_file
        self.header = None
        self.manifest = None
        self.data_offset = None
        self.metadata_signature = None
        self.metadata_size = None

    def _read_manifest(self) -> bytes:
        return self.payload_file.read(self.header.manifest_len)

    def _read_metadata_signature(self) -> bytes:
        self.payload_file.seek(self.header.size + self.header.manifest_len)
        return self.payload_file.read(self.header.metadata_signature_len)

    def read_data_blob(self, offset: int, length: int) -> bytes:
        self.payload_file.seek(self.data_offset + offset)
        return self.payload_file.read(length)

    def init(self) -> None:
        self.header = self._PayloadHeader()
        self.header.read_from_payload(self.payload_file)
        manifest_raw = self._read_manifest()
        self.manifest = update_metadata_pb2.DeltaArchiveManifest()
        try:
            self.manifest.ParseFromString(manifest_raw)
        except message.DecodeError as parse_error:
            print(f'[WARN] Cannot deserialize Protobuf. Reason: {parse_error}')
        metadata_signature_raw = self._read_metadata_signature()
        if metadata_signature_raw:
            self.metadata_signature = update_metadata_pb2.Signatures()
            self.metadata_signature.ParseFromString(metadata_signature_raw)
        self.metadata_size = self.header.size + self.header.manifest_len
        self.data_offset = self.metadata_size + self.header.metadata_signature_len


def check_local_tools() -> None:
    missing_tools = []
    if not shutil.which("xzcat"):
        missing_tools.append("xzcat")
    if not shutil.which("bzcat"):
        missing_tools.append("bzcat")

    if missing_tools:
        raise PayloadError(
            f"Missing required local tools: {', '.join(missing_tools)}. Please install them or do not use --use-local-tools.")


def decompress_payload(command: str, data: bytes, size: int, expected_hash: bytes) -> bytes:
    p = subprocess.Popen([command, '-'], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    r = p.communicate(data)[0]
    validate_decompression(r, data, size, expected_hash)
    return r


def decompress_payload_fallback(compression_type: str, data: bytes, size: int, expected_hash: bytes) -> bytes:
    result = None
    try:
        if compression_type == 'xz':
            result = lzma.decompress(data)
        elif compression_type == 'bz2':
            result = bz2.decompress(data)
        validate_decompression(result, data, size, expected_hash)
    except (lzma.LZMAError, IOError) as err_decompress:
        print(f"{compression_type.upper()} decompression failed: {err_decompress}")
    return result


def validate_decompression(result: bytes, data: bytes, expected_size: int, expected_hash: bytes) -> None:
    if len(result) != expected_size:
        print(f"Unexpected size {len(result)} {expected_size}")
    elif hashlib.sha256(data).digest() != expected_hash:
        print("Hash mismatch")


def display_progress(current: int, total: int) -> None:
    progress = int((current / total) * 50)
    bar = '=' * progress + '-' * (50 - progress)
    sys.stdout.write(f'\r[{bar}] {current}/{total}')
    sys.stdout.flush()


def parse_payload(payload_f: Payload, partition, out_f, use_local_tools: bool) -> None:
    total_operations = len(partition.operations)

    for index, operation in enumerate(partition.operations):
        extent = operation.dst_extents[0]
        data = payload_f.read_data_blob(operation.data_offset, operation.data_length)
        out_f.seek(extent.start_block * BLOCK_SIZE)
        operation_type = operation.type

        decompression_function = (
            decompress_payload
            if use_local_tools else
            decompress_payload_fallback
        )

        if operation_type == update_metadata_pb2.InstallOperation.REPLACE:
            out_f.write(data)
        elif operation_type in [update_metadata_pb2.InstallOperation.REPLACE_XZ,
                                update_metadata_pb2.InstallOperation.REPLACE_BZ]:
            comp_type = 'xz' if operation_type == update_metadata_pb2.InstallOperation.REPLACE_XZ else 'bz2'
            cmd = 'xzcat' if comp_type == 'xz' else 'bzcat'
            decompress_function = lambda d, s, h: decompression_function(cmd, d, s,
                                                                         h) if use_local_tools else decompression_function(
                comp_type, d, s, h)
            r = decompress_function(data, extent.num_blocks * BLOCK_SIZE, operation.data_sha256_hash)
            if r:
                out_f.write(r)
        elif operation_type == update_metadata_pb2.InstallOperation.ZERO:
            out_f.write(b'\x00' * (extent.num_blocks * BLOCK_SIZE))
        else:
            raise PayloadError(
                f'Unhandled operation type ({operation_type} - {update_metadata_pb2.InstallOperation.Type.Name(operation_type)})')

        display_progress(index + 1, total_operations)
    print()


def extract_android_ota_payload(filename: Path, output_dir: Path, use_local_tools: bool) -> None:
    output_dir = output_dir.resolve()
    if output_dir != Path.cwd() and output_dir.exists() and any(output_dir.iterdir()):
        response = input(
            f"Target directory '{output_dir}' already exists and is not empty. Overwrite contents? (Y/n): ").strip().lower()
        if response not in ('y', ''):
            print("Operation cancelled by user.")
            sys.exit(0)

    if filename.suffix == '.zip':
        print(f"Opening ZIP file {filename} to extract to {output_dir}...")
        with ZipFile(filename) as ota_zf:
            payload_file_path = ota_zf.extract('payload.bin', output_dir)
            payload_file = open(payload_file_path, 'rb')
    else:
        print(f"Opening file {filename} for extraction to {output_dir}...")
        payload_file = open(filename, 'rb')

    print(f"Extracting to target directory: {output_dir}")

    payload = Payload(payload_file)
    payload.init()

    for p in payload.manifest.partitions:
        name = f'{p.partition_name}.img'
        print(f"Extracting '{name}'")
        fname = output_dir / name
        with open(fname, 'wb') as out_f:
            try:
                parse_payload(payload, p, out_f, use_local_tools)
            except PayloadError as err_extract:
                print(f'Error: {err_extract}')
                out_f.close()
                os.unlink(fname)
                if use_local_tools:
                    sys.exit(1)


# noinspection PyUnusedLocal
def signal_handler(signal_received, frame) -> None:
    print("\nOperation cancelled by user.")
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(
        description="Extract Android OTA payload.",
        usage="extract_android_ota_payload.py <payload.bin> [target_dir] [--use-local-tools]\n"
              "  <payload.bin>       : file extracted from the OTA zip file or the OTA zip file\n"
              "  [target_dir]        : output directory for the extracted file (default: './output')\n"
              "  [--use-local-tools] : use local xzcat and bzcat if available"
    )
    parser.add_argument("filename", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("output_dir", type=Path, nargs='?', default=Path('output'), help=argparse.SUPPRESS)
    parser.add_argument("--use-local-tools", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    try:
        if args.use_local_tools:
            check_local_tools()
        extract_android_ota_payload(args.filename, args.output_dir, args.use_local_tools)
    except PayloadError as e:
        print(e)
        sys.exit(1)
