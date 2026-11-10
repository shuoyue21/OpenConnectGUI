#!/usr/bin/env python3
"""Bundle a trusted OpenConnect runtime and produce a root-owned macOS installer.

Does not install, register a daemon, edit sudoers, or start a VPN. Run only on a
trusted build machine: the selected OpenConnect distribution is executable code.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def output(*args):
    return run(*args, stdout=subprocess.PIPE, text=True).stdout


def system_library(path):
    return path.startswith('/usr/lib/') or path.startswith('/System/Library/')


def load_paths(binary):
    lines = output('/usr/bin/otool', '-l', binary).splitlines()
    paths = []
    for i, line in enumerate(lines):
        if line.strip() == 'cmd LC_RPATH':
            paths.append(lines[i + 2].strip().split('path ', 1)[1].split(' (offset', 1)[0])
    return paths


def dependencies(binary):
    return [line.strip().split(' (compatibility version', 1)[0]
            for line in output('/usr/bin/otool', '-L', binary).splitlines()[1:]]


def resolve_library(name, parent, executable):
    def expand(path):
        return path.replace('@loader_path', str(parent.parent)).replace('@executable_path', str(executable.parent))
    if name.startswith('@rpath/'):
        for search in load_paths(parent) + load_paths(executable):
            candidate = Path(expand(search)) / name.removeprefix('@rpath/')
            if candidate.is_file():
                return candidate.resolve()
        raise RuntimeError(f'Cannot resolve {name} required by {parent}')
    candidate = Path(expand(name))
    if not candidate.is_absolute() or not candidate.is_file():
        raise RuntimeError(f'Unsupported or missing dependency: {name}')
    return candidate.resolve()


def bundle_runtime(app, executable, script, ca_bundle):
    runtime = app / 'Contents/Resources/OpenConnect'
    if runtime.exists():
        shutil.rmtree(runtime)
    (runtime / 'bin').mkdir(parents=True)
    (runtime / 'lib').mkdir()
    (runtime / 'licenses').mkdir()
    executable = executable.resolve()
    copied = {executable: runtime / 'bin/openconnect'}
    pending = [executable]
    edges = {}
    names = {}
    while pending:
        source = pending.pop()
        target = copied[source]
        shutil.copy2(source, target)
        edges[source] = []
        for name in dependencies(source):
            if system_library(name):
                continue
            dependency = resolve_library(name, source, executable)
            if dependency == source:  # LC_ID_DYLIB
                continue
            edges[source].append((name, dependency))
            if dependency not in copied:
                if dependency.name in names and names[dependency.name] != dependency:
                    raise RuntimeError(f'Conflicting dependency names: {dependency.name}')
                names[dependency.name] = dependency
                copied[dependency] = runtime / 'lib' / dependency.name
                pending.append(dependency)
    for source, target in copied.items():
        changes = []
        for old, dependency in edges[source]:
            relative = os.path.relpath(copied[dependency], target.parent)
            changes += ['-change', old, '@loader_path/' + relative]
        for rpath in load_paths(target):
            changes += ['-delete_rpath', rpath]
        if source != executable:
            changes += ['-id', '@loader_path/' + target.name]
        if changes:
            run('/usr/bin/install_name_tool', *changes, target)
        for name in dependencies(target):
            if not (system_library(name) or name.startswith('@loader_path/')):
                raise RuntimeError(f'Unbundled library reference in {target}: {name}')
        # Preserve package notices and formula metadata alongside the local runtime.
        parts = source.parts
        if 'Cellar' in parts:
            index = parts.index('Cellar')
            formula_root = Path(*parts[:index + 3])
            notices = runtime / 'licenses' / parts[index + 1]
            notices.mkdir(exist_ok=True)
            for candidate in formula_root.iterdir():
                if candidate.is_file() and re.search(r'license|copying|copyright|notice', candidate.name, re.I):
                    shutil.copy2(candidate, notices / candidate.name)
            if (formula_root / '.brew').is_dir():
                shutil.copytree(formula_root / '.brew', notices / 'formula', dirs_exist_ok=True)
    script_text = script.read_text().replace('basename $0', 'basename "$0"').replace('readlink -f $0', 'readlink -f "$0"')
    # Root must not source independently managed hooks. Keep hook lookup inside the protected bundle.
    fixed_hooks = '/Library/Application Support/OpenConnectGUI/runtime/OpenConnect/hooks'
    if 'HOOKS_DIR=/etc/vpnc' not in script_text:
        raise RuntimeError('Unrecognized vpnc-script; audit its hook loading before packaging.')
    script_text = script_text.replace('HOOKS_DIR=/etc/vpnc', f'HOOKS_DIR="{fixed_hooks}"')
    # This upstream script does not quote HOOKS_DIR in run_hooks; use a fixed empty directory with no hooks.
    begin = script_text.index('run_hooks() {')
    end = script_text.index('\n}', begin) + 2
    script_text = script_text[:begin] + 'run_hooks() {\n    : # External hook execution is disabled in the packaged VPN runtime.\n}' + script_text[end:]
    script_text = script_text.replace(
        """netstat -r -n $netstat_syntax_ipv6 | awk '/^(default|::\\/0)/ { if ($NF!~/^lo/ && $NF!~/'"$TUNDEV"'([[:space:]]|$)/) { print ($2~/^fe[89ab]/ ? $2"%"$NF : $2); } }'""",
        """netstat -r -n $netstat_syntax_ipv6 | awk '/^(default|::\\/0)/ { if ($NF!~/^(lo|utun)/ && $NF!~/'"$TUNDEV"'([[:space:]]|$)/ && $2!~/^fe80::%/) { print ($2~/^fe[89ab]/ && $2!~/%/ ? $2"%"$NF : $2); exit; } }'"""
    )
    (runtime / 'vpnc-script').write_text(script_text)
    (runtime / 'hooks').mkdir()
    shutil.copy2(ca_bundle, runtime / 'ca-bundle.pem')
    (runtime / 'vpnc-script').chmod(0o755)
    manifest = [{'source': str(source), 'bundled': str(target.relative_to(runtime)),
                 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
                for source, target in copied.items()]
    (runtime / 'build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return runtime, list(copied.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True, help='Already-built .app (includes helper and LaunchDaemon plist)')
    parser.add_argument('--openconnect', type=Path, required=True)
    parser.add_argument('--vpnc-script', type=Path, required=True)
    parser.add_argument('--ca-bundle', type=Path, default=Path('/etc/ssl/cert.pem'))
    parser.add_argument('--output', type=Path, required=True, help='New output directory; must not already exist')
    parser.add_argument('--sign-identity', help='Developer ID Application identity (required to create an installer)')
    parser.add_argument('--verify-runtime-only', action='store_true', help='Copy and smoke-test runtime as the ordinary user; no installable package or privileged service')
    parser.add_argument('--installer-identity', help='Optional Developer ID Installer identity')
    parser.add_argument('--version', default='1.0.1')
    args = parser.parse_args()
    if not args.verify_runtime_only and (not args.sign_identity or args.sign_identity == '-'):
        parser.error('An installer requires a Developer ID Application signing identity. Use --verify-runtime-only for an unprivileged packaging check.')
    args.output.mkdir(parents=True, exist_ok=False)
    root = args.output / 'payload'
    root.mkdir()
    app = root / 'OpenconnectGUI.app'
    shutil.copytree(args.app, app, symlinks=False)
    helper = app / 'Contents/Library/HelperTools/OpenConnectHelper'
    plist = app / 'Contents/Library/LaunchDaemons/mjucha.OpenconnectGUI.helper.plist'
    if not helper.is_file() or not plist.is_file():
        raise RuntimeError('Build the OpenconnectGUI scheme, including its helper target, before packaging.')
    runtime, binaries = bundle_runtime(app, args.openconnect, args.vpnc_script, args.ca_bundle)
    for path in app.rglob('*'):
        if path.is_symlink():
            raise RuntimeError(f'Unexpected symlink in package: {path}')
        path.chmod(0o755 if path.is_dir() or os.access(path, os.X_OK) else 0o644)
    identity = args.sign_identity or '-'
    sign_options = ['--force', '--sign', identity]
    if not args.verify_runtime_only:
        sign_options += ['--options', 'runtime', '--timestamp']
    else:
        sign_options += ['--timestamp=none']
    for binary in binaries + [helper]:
        run('/usr/bin/codesign', *sign_options, binary)
    run('/usr/bin/codesign', *sign_options, app)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
    # Smoke test executes only --version as the ordinary build user; no VPN or root operation.
    version = output(runtime / 'bin/openconnect', '--version')
    (args.output / 'runtime-version.txt').write_text(version)
    if args.verify_runtime_only:
        print('Unprivileged runtime smoke test passed. This staging app is NOT an installable privileged-service build.')
        return
    # Check the supplied identity really produced a Developer ID application before packaging.
    run('/usr/bin/codesign', '--verify', '--strict', '-R',
        'anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists', app)
    scripts = args.output / 'installer-scripts'
    scripts.mkdir()
    postinstall = scripts / 'postinstall'
    postinstall.write_text('''#!/bin/sh
set -eu
app="/Library/Application Support/OpenConnectGUI/OpenconnectGUI.app"
# pkgbuild installs the payload as root:wheel. Remove inherited ACL grants too.
/usr/sbin/chown root:wheel "/Library/Application Support/OpenConnectGUI"
/bin/chmod -N "/Library/Application Support/OpenConnectGUI"
/bin/chmod 0755 "/Library/Application Support/OpenConnectGUI"
/usr/sbin/chown -R root:wheel "$app"
/bin/chmod -RN "$app"
/bin/chmod -R go-w "$app"
exit 0
''')
    postinstall.chmod(0o755)
    command = ['/usr/bin/pkgbuild', '--root', str(root), '--ownership', 'recommended',
               '--install-location', '/Library/Application Support/OpenConnectGUI',
               '--identifier', 'mjucha.OpenconnectGUI', '--version', args.version, '--scripts', str(scripts)]
    if args.installer_identity:
        command += ['--sign', args.installer_identity]
    command.append(str(args.output / 'OpenconnectGUI.pkg'))
    run(*command)
    print(f'Created {args.output / "OpenconnectGUI.pkg"}; no installation or system changes performed.')


if __name__ == '__main__':
    main()
