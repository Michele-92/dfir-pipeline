from pathlib import Path


def detect_format(magic_output: str) -> str:
    raw = magic_output.lower()
    if 'ewf' in raw or 'expert witness' in raw:
        return 'E01'
    if 'vmware' in raw or 'vmdk' in raw:
        return 'VMDK'
    if 'microsoft' in raw and 'vhd' in raw:
        return 'VHDX'
    if 'qemu' in raw or 'qcow' in raw:
        return 'QCOW2'
    if 'aff' in raw:
        return 'AFF'
    return 'DD'


def detect_format_by_extension(path: Path) -> str:
    suffix = path.suffix.lower()
    mapping = {
        '.e01': 'E01', '.ex01': 'E01',
        '.dd':  'DD',  '.raw':  'DD', '.img': 'DD',
        '.vmdk': 'VMDK',
        '.vhd':  'VHDX', '.vhdx': 'VHDX',
        '.qcow2': 'QCOW2', '.qcow': 'QCOW2',
        '.aff':  'AFF',
    }
    return mapping.get(suffix, 'DD')
