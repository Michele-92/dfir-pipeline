import subprocess
import json
import logging
from pathlib import Path

from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

VOL_PLUGINS = [
    'linux.pslist',
    'linux.pstree',
    'linux.netstat',
    'linux.bash',
    'linux.malfind',
    'linux.modules',
    'linux.capabilities',
    'linux.envars',
    'linux.sockstat',
    'linux.lsof',
]


def run(ctx: PipelineContext) -> PipelineContext:
    if not ctx.ram_dump_path:
        log.info('Stage 2: Kein RAM-Dump angegeben — übersprungen')
        ctx.stage_status['stage_02'] = 'ÜBERSPRUNGEN'
        return ctx

    log.info(f'Stage 2: RAM-Analyse von {ctx.ram_dump_path}')
    results = {}

    for plugin in VOL_PLUGINS:
        try:
            out = _run_volatility(ctx.ram_dump_path, plugin)
            results[plugin] = out
            log.info(f'  Volatility {plugin}: {len(out)} Einträge')
        except Exception as e:
            log.warning(f'  Plugin {plugin} fehlgeschlagen: {e}')
            results[plugin] = []

    ctx.memory_results = results
    if ctx.coc:
        ctx.coc.add_entry('stage_02', f'RAM-Analyse: {len(VOL_PLUGINS)} Plugins')
    return ctx


def _run_volatility(ram_path: Path, plugin: str) -> list:
    result = subprocess.run(
        ['python3', '-m', 'volatility3', '-f', str(ram_path),
         plugin, '--output', 'json'],
        capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr[:200])
    try:
        data = json.loads(result.stdout)
        return data.get('rows', [])
    except (json.JSONDecodeError, AttributeError):
        return []
