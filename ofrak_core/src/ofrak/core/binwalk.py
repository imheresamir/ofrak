import asyncio
from concurrent.futures.process import ProcessPoolExecutor
from dataclasses import dataclass
import json
import os
import shutil
import subprocess
import tempfile
from typing import Dict

from ofrak.resource import ResourceFactory, Resource

from ofrak.model.resource_model import ResourceAttributes

from ofrak.component.abstract import ComponentMissingDependencyError
from ofrak.component.analyzer import Analyzer

BINWALK_INSTALLED = shutil.which("binwalk") is not None

from ofrak.core.binary import GenericBinary
from ofrak.model.component_model import ComponentExternalTool
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface


class _BinwalkExternalTool(ComponentExternalTool):
    def __init__(self):
        super().__init__(
            "binwalk",
            "https://github.com/ReFirmLabs/binwalk",
            install_check_arg="",
        )

    async def is_tool_installed(self) -> bool:
        return BINWALK_INSTALLED


BINWALK_TOOL = _BinwalkExternalTool()


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class BinwalkAttributes(ResourceAttributes):
    offsets: Dict[int, str]


class BinwalkAnalyzer(Analyzer[None, BinwalkAttributes]):
    """
    Uses the binwalk tool to scan binary data for embedded files, filesystems, compressed data,
    bootloaders, and known file signatures. Binwalk identifies file offsets and types based on magic
    bytes and header patterns. Use for initial triage of unknown firmware or binaries to discover
    what's embedded inside, identify compressed sections, find filesystem boundaries, or locate
    interesting artifacts without manually parsing. This is a good first step in the firmware
    analysis workflow if OFRAK cannot automatically identify and unpack a given firmware - once
    binwalk identifies firmware chunk boundaries, create children for each chunk and use the OFRAK
    firmware analysis workflows accordingly. If using the GUI, use the "Carve Child" button to
    create these children.
    """

    targets = (GenericBinary,)
    outputs = (BinwalkAttributes,)
    external_dependencies = (BINWALK_TOOL,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.pool = ProcessPoolExecutor()

    async def analyze(self, resource: Resource, config=None) -> BinwalkAttributes:
        if not BINWALK_INSTALLED:
            raise ComponentMissingDependencyError(self, BINWALK_TOOL)
        async with resource.temp_to_disk() as temp_path:
            # Should errors be handled the way they are in the `DataSummaryAnalyzer`? Likely to be
            # overkill here.
            offsets = await asyncio.get_running_loop().run_in_executor(
                self.pool, _run_binwalk_on_file, temp_path
            )
        return BinwalkAttributes(offsets)


def _run_binwalk_on_file(filename):  # pragma: no cover
    offsets = dict()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        json_path = tmp.name
    try:
        subprocess.run(
            ["binwalk", "--log", json_path, filename],
            capture_output=False,
            text=True,
            check=True
        )
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            analysis = data[0].get("Analysis", {})
            file_map = analysis.get("file_map", [])
        else:
            file_map = []
        for entry in file_map:
            offset = entry.get("offset") or entry.get("decimal") or 0
            description = entry.get("description", "")
            if offset:
                offsets[offset] = description
        return offsets
    finally:
        if os.path.exists(json_path):
            os.unlink(json_path)
