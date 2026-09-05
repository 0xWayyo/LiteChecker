"""Execute the real menu with isolated installation roots and fake service commands."""
import os
from pathlib import Path
import shutil
import subprocess
import pty
import re
import select
import time
import unicodedata
import fcntl
import struct
import termios

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')


@pytest.fixture
def installation(tmp_path):
    source = tmp_path / "Архив Ивана's LiteChecker"
    (source / 'scripts').mkdir(parents=True)
    controller = ROOT / 'scripts/control.sh'
    if controller.exists():
        shutil.copy2(controller, source / 'scripts/control.sh')
    canonical = tmp_path / 'Library/Application Support/LiteChecker'
    (canonical / 'scripts').mkdir(parents=True)
    (canonical / 'secrets').mkdir()
    (canonical / 'native-settings.json').write_text('{}')
    for name in ('telegram_bot_token', 'subscription_url'):
        (canonical / 'secrets' / name).write_text('never-print-this-secret')
    runtime = canonical / '.native-direct/venv/bin/python'
    runtime.parent.mkdir(parents=True)
    runtime.write_text('#!/bin/bash\nprintf "settings:%s\\n" "$*" >> "$CALLS"\nexit "${SETUP_EXIT:-0}"\n')
    runtime.chmod(0o700)
    (canonical / 'run.sh').write_text('''#!/bin/bash
printf 'run:%s\\n' "$*" >> "$CALLS"
case "$1" in
status) printf '%s\\n' "${STATUS_TEXT:-state = running}"; exit "${STATUS_EXIT:-0}";;
start|stop) exit "${ACTION_EXIT:-0}";;
*) exit 97;;
esac
''')
    (source / 'scripts/install.sh').write_text('#!/bin/bash\nprintf "install\\n" >> "$CALLS"\nexit 0\n')
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    (bindir / 'uname').write_text('#!/bin/bash\necho Darwin\n')
    (bindir / 'uname').chmod(0o700)
    env = {**os.environ, 'PATH': str(bindir) + os.pathsep + os.environ['PATH'],
           'LITECHECKER_NATIVE_ROOT': str(canonical), 'CALLS': str(tmp_path / 'calls')}
    return source, canonical, env


def run_menu(installation, action='menu', inputs=''):
    source, _, env = installation
    script = source / 'scripts/control.sh'
    assert script.exists(), 'terminal controller has not been implemented'
    return subprocess.run([BASH, str(script), action], input=inputs, text=True,
                          capture_output=True, env=env, cwd=source.parent, timeout=5)


def calls(installation):
    path = Path(installation[2]['CALLS'])
    return path.read_text().splitlines() if path.exists() else []


def test_reopening_and_exiting_never_reinstalls_or_starts(installation):
    result = run_menu(installation, inputs='0\n')
    assert result.returncode == 0, result.stderr
    assert 'Остановить проверки' in result.stdout and 'Запустить проверки' not in result.stdout
    assert str(installation[1]) not in result.stdout
    assert '🟢' in result.stdout and 'РАБОТАЕТ' in result.stdout
    assert calls(installation) == ['run:status']
    assert 'never-print-this-secret' not in result.stdout + result.stderr


@pytest.mark.parametrize('action', ['start', 'stop'])
def test_actions_use_canonical_managed_launcher_not_extracted_code(installation, action):
    result = run_menu(installation, action)
    assert result.returncode == 0, result.stderr
    assert calls(installation) == ['run:' + action]


def test_failed_stop_is_not_reported_as_success(installation):
    installation[2]['ACTION_EXIT'] = '9'
    result = run_menu(installation, 'stop')
    assert result.returncode == 9
    assert 'Не удалось' in result.stdout + result.stderr
    assert 'остановлен.' not in result.stdout.lower()


def test_status_failure_is_unknown_not_stopped(installation):
    installation[2].update(STATUS_EXIT='1', STATUS_TEXT='Permission denied')
    result = run_menu(installation, 'status')
    assert 'Не удалось определить' in result.stdout
    assert 'Остановлен' not in result.stdout


def test_missing_native_service_is_stopped(installation):
    installation[2].update(STATUS_EXIT='113', STATUS_TEXT='Could not find service "com.litechecker.direct" in domain')
    result = run_menu(installation, 'status')
    assert 'Остановлен' in result.stdout


def test_menu_eof_and_invalid_selection_do_not_mutate(installation):
    result = run_menu(installation, inputs='bad\n')
    assert result.returncode == 0
    assert calls(installation) == ['run:status', 'run:status']


def test_settings_cancel_does_not_stop_or_modify(installation):
    result = run_menu(installation, 'settings', inputs='n\n')
    assert result.returncode == 0
    assert calls(installation) == []


def test_settings_explicit_confirmation_stops_then_edits_and_never_restarts(installation):
    result = run_menu(installation, 'settings', inputs='y\n')
    assert result.returncode == 0, result.stderr
    recorded = calls(installation)
    assert recorded[0] == 'run:stop'
    assert recorded[1].startswith('settings:-m litechecker.device_setup --root ')
    assert recorded[1].endswith('--system native')
    assert len(recorded) == 2


def test_settings_does_not_edit_when_stop_failed(installation):
    installation[2]['ACTION_EXIT'] = '12'
    result = run_menu(installation, 'settings', inputs='y\n')
    assert result.returncode == 12
    assert calls(installation) == ['run:stop']


def test_recent_log_returns_to_menu_instead_of_following_forever(installation):
    state = installation[1] / 'state/native-direct'
    state.mkdir(parents=True)
    (state / 'service.log').write_text('\n'.join(f'cycle-{n}' for n in range(100)))
    result = run_menu(installation, 'logs')
    assert result.returncode == 0, result.stderr
    assert 'cycle-99' in result.stdout and 'cycle-0\n' not in result.stdout
    assert calls(installation) == []


def test_log_symlink_is_not_read(installation):
    state = installation[1] / 'state/native-direct'
    state.mkdir(parents=True)
    (state / 'service.log').symlink_to(installation[1] / 'secrets/telegram_bot_token')
    result = run_menu(installation, 'logs')
    assert result.returncode != 0
    assert 'never-print-this-secret' not in result.stdout + result.stderr


def test_linux_logs_supply_required_compose_identity(installation):
    source, _, env = installation
    bindir = Path(env['PATH'].split(os.pathsep)[0])
    (bindir / 'uname').write_text('#!/bin/bash\necho Linux\n')
    for name in ('.env.standalone', 'compose.standalone.yml'):
        (source / name).write_text('synthetic-compose-input\n')
    docker = bindir / 'docker'
    docker.write_text('#!/bin/bash\n: "${LITECHECKER_UID:?missing UID}" "${LITECHECKER_GID:?missing GID}"\nprintf "compose:%s:%s:%s\\n" "$LITECHECKER_UID" "$LITECHECKER_GID" "$*" >> "$CALLS"\nprintf "recent-cycle\\n"\n')
    docker.chmod(0o700)
    env.pop('LITECHECKER_UID', None)
    env.pop('LITECHECKER_GID', None)
    env.pop('WSL_DISTRO_NAME', None)
    result = run_menu(installation, 'logs')
    assert result.returncode == 0, result.stderr
    assert calls(installation) == [f'compose:{os.getuid()}:{os.getgid()}:compose --env-file .env.standalone -f compose.standalone.yml logs --tail 80 checker']
    assert 'recent-cycle' in result.stdout


@pytest.mark.parametrize('system', ['Darwin', 'Linux'])
def test_failed_log_read_is_not_reported_as_success(installation, system):
    source, root, env = installation
    bindir = Path(env['PATH'].split(os.pathsep)[0])
    (bindir / 'uname').write_text(f'#!/bin/bash\necho {system}\n')
    if system == 'Darwin':
        log = root / 'state/native-direct/service.log'
        log.parent.mkdir(parents=True)
        log.write_text('cycle\n')
        command = bindir / 'tail'
    else:
        for name in ('.env.standalone', 'compose.standalone.yml'):
            (source / name).write_text('synthetic-compose-input\n')
        env.pop('WSL_DISTRO_NAME', None)
        command = bindir / 'docker'
    command.write_text('#!/bin/bash\nexit 17\n')
    command.chmod(0o700)
    result = run_menu(installation, 'logs')
    assert result.returncode == 17
    assert 'Показаны последние' not in result.stdout
    assert 'Не удалось прочитать журнал' in result.stdout + result.stderr


def test_fresh_menu_exit_has_no_install_side_effects(installation):
    (installation[1] / 'native-settings.json').unlink()
    result = run_menu(installation, inputs='0\n')
    assert result.returncode == 0
    assert 'Установить' in result.stdout
    assert calls(installation) == []


def test_cancelled_initial_setup_is_offered_setup_again_not_start(installation):
    (installation[1] / 'secrets/telegram_bot_token').unlink()
    result = run_menu(installation, inputs='0\n')
    assert result.returncode == 0
    assert '1  Установить и настроить' in result.stdout
    assert '1  Запустить' not in result.stdout
    assert calls(installation) == []


def test_manual_update_uses_signed_updater_and_forces_fresh_check(installation):
    script = installation[1] / 'scripts/update.sh'
    script.write_text('#!/bin/bash\nprintf "update:%s\\n" "$*" >> "$CALLS"\nprintf \'{"status": "updated", "version": "0.4.0"}\\n\'\n')
    result = run_menu(installation, 'update')
    assert result.returncode == 0, result.stderr
    assert calls(installation) == ['update:check --force']
    assert 'Новая версия установлена' in result.stdout
    assert '{"status"' not in result.stdout


def test_failed_manual_update_never_claims_new_version_installed(installation):
    script = installation[1] / 'scripts/update.sh'
    script.write_text('#!/bin/bash\nprintf \'{"status":"failed","error":"updater-command-failed"}\\n\'\nexit 1\n')
    result = run_menu(installation, 'update')
    assert result.returncode == 1
    assert 'Обновление не завершено' in result.stdout + result.stderr
    assert 'Новая версия установлена' not in result.stdout


@pytest.mark.parametrize('entry', ['INSTALL.command', 'INSTALL.sh'])
def test_interactive_install_entry_opens_control_not_installer(installation, entry):
    source, _, env = installation
    shutil.copy2(ROOT / entry, source / entry)
    (source / 'scripts/control.sh').write_text('#!/bin/bash\nprintf "menu\\n" >> "$CALLS"\n')
    master, slave = pty.openpty()
    try:
        result = subprocess.run([BASH, str(source / entry)], stdin=slave,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env, timeout=5)
    finally:
        os.close(master)
        os.close(slave)
    assert result.returncode == 0, result.stderr
    assert calls(installation) == ['menu']


def test_native_configuration_cli_calls_wizard_after_importing_presets(monkeypatch, tmp_path):
    from litechecker import native_install
    from litechecker import device_setup
    events = []
    monkeypatch.setattr(native_install, 'install_configuration', lambda *args: events.append('import'))
    monkeypatch.setattr(device_setup, 'configure_device', lambda root, system, **kw: events.append((root, system, kw)) or 2)
    assert native_install.main(['--source', str(tmp_path), '--root', str(tmp_path),
                                '--plist', str(tmp_path / 'agent.plist'), '--configure']) == 2
    assert events == ['import', (tmp_path, 'native', {'initial': True})]


def test_successful_mac_install_hands_off_before_returning_to_menu(installation):
    (installation[1] / 'scripts/control.sh').write_text('#!/bin/bash\n')
    result = run_menu(installation, 'install')
    assert result.returncode == 0, result.stderr
    recorded = calls(installation)
    assert recorded[0] == 'install'
    assert recorded[1].startswith('settings:-m litechecker.install_handoff --source ')
    assert recorded[1].endswith('--root ' + str(installation[1]))


def test_failed_install_never_attempts_handoff_cleanup(installation):
    (installation[1] / 'scripts/control.sh').write_text('#!/bin/bash\n')
    (installation[0] / 'scripts/install.sh').write_text('#!/bin/bash\nprintf "install\\n" >> "$CALLS"\nexit 5\n')
    result = run_menu(installation, 'install')
    assert result.returncode == 5
    assert calls(installation) == ['install']


@pytest.mark.parametrize('raw, code, icon, label, primary', [
    ('state = running', '0', '🟢', 'РАБОТАЕТ', 'Остановить проверки'),
    ('Could not find service', '113', '🔴', 'ОСТАНОВЛЕН', 'Запустить проверки'),
    ('state = spawn scheduled', '0', '🟡', 'ЗАПУСКАЕТСЯ', 'Остановить проверки'),
    ('Permission denied', '1', '❔', 'СТАТУС НЕИЗВЕСТЕН', 'Обновить статус'),
])
def test_menu_primary_matches_observed_state(installation, raw, code, icon, label, primary):
    installation[2].update(STATUS_TEXT=raw, STATUS_EXIT=code)
    result = run_menu(installation, inputs='0\n')
    assert icon in result.stdout and label in result.stdout
    assert '1  ' + primary in result.stdout
    assert '8  ' not in result.stdout and '6  ' not in result.stdout
    assert 'Восстановить' not in result.stdout


def test_primary_stops_running_checker_not_starts_it_again(installation):
    result = run_menu(installation, inputs='1\n0\n')
    assert result.returncode == 0
    assert 'run:stop' in calls(installation)
    assert 'run:start' not in calls(installation)


def test_primary_never_changes_meaning_when_state_changes_during_choice(installation):
    root = installation[1]
    (root / 'run.sh').write_text('''#!/bin/bash
printf 'run:%s\\n' "$*" >> "$CALLS"
if [[ "$1" == status ]]; then
  if [[ -e "$CALLS.seen" ]]; then printf 'state = running\\n'; else
    touch "$CALLS.seen"; printf 'Could not find service\\n'; exit 113
  fi
fi
''')
    result = run_menu(installation, inputs='1\n0\n')
    assert 'run:stop' not in calls(installation)
    assert 'run:start' not in calls(installation)
    assert 'Состояние изменилось' in result.stdout


def test_start_rechecks_actual_status_instead_of_claiming_running(installation):
    installation[2].update(STATUS_TEXT='Could not find service', STATUS_EXIT='113')
    result = run_menu(installation, inputs='1\n0\n')
    assert calls(installation).count('run:status') >= 3
    assert calls(installation).count('run:start') == 1
    assert 'РАБОТАЕТ' not in result.stdout
    assert 'Чекер работает' not in result.stdout


def test_settings_submenu_can_be_opened_without_stopping_checker(installation):
    result = run_menu(installation, inputs='3\n0\n0\n')
    assert 'Дополнительно' in result.stdout
    assert 'run:stop' not in calls(installation)
    assert not any(line.startswith('settings:') for line in calls(installation))


def test_technical_paths_are_only_in_nested_additional_menu(installation):
    result = run_menu(installation, inputs='3\n2\n1\n0\n0\n0\n')
    assert str(installation[1]) in result.stdout
    assert 'run:stop' not in calls(installation)
    assert 'install' not in calls(installation)


@pytest.mark.parametrize('columns', [38, 80])
@pytest.mark.parametrize('locale', ['C', 'en_US.UTF-8'])
def test_frame_uses_terminal_cells_and_fits_narrow_width(installation, columns, locale):
    installation[2].update(COLUMNS=str(columns), LC_ALL=locale, NO_COLOR='1')
    result = run_menu(installation, inputs='0\n')
    rows = [line for line in result.stdout.splitlines() if any(char in line for char in '┌┐└┘│')]
    assert len(rows) >= 4
    widths = [sum(2 if unicodedata.east_asian_width(char) in 'WF' else 1 for char in row) for row in rows]
    assert len(set(widths)) == 1, rows
    assert max(widths) <= columns
    assert '\x1b[' not in result.stdout


def test_native_nested_state_does_not_override_top_level_state(installation):
    installation[2]['STATUS_TEXT'] = 'gui/501/com.litechecker.direct = {\n\tstate = spawn scheduled\n\tresource coalition = {\n\t\tstate = running\n\t}\n}'
    result = run_menu(installation, inputs='0\n')
    assert 'ЗАПУСКАЕТСЯ' in result.stdout
    assert 'РАБОТАЕТ' not in result.stdout


def test_terminal_refreshes_status_without_user_action_or_probe(installation):
    source, root, env = installation
    state = source.parent / 'observed-state'
    state.write_text('state = running\n')
    env.update(OBSERVED_STATE=str(state), TERM='xterm-256color', NO_COLOR='1')
    (root / 'run.sh').write_text('''#!/bin/bash
printf 'run:%s\\n' "$*" >> "$CALLS"
if [[ "$1" == status ]]; then cat "$OBSERVED_STATE"; else exit 99; fi
''')
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    process = subprocess.Popen([BASH, str(source / 'scripts/control.sh')], stdin=slave,
                               stdout=slave, stderr=slave, env=env)
    os.close(slave)
    output = bytearray()
    def wait_for(text, seconds=12):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if text.encode() in output:
                return
            if select.select([master], [], [], 0.1)[0]:
                output.extend(os.read(master, 65536))
        pytest.fail('Expected terminal state not rendered: ' + text)
    try:
        wait_for('РАБОТАЕТ')
        state.write_text('state = spawn scheduled\n')
        wait_for('ЗАПУСКАЕТСЯ')
        os.write(master, b'0\n')
        process.wait(timeout=5)
        assert process.returncode == 0
        assert all(line == 'run:status' for line in calls(installation))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)


def test_key_entered_during_auto_refresh_cannot_run_opposite_action(installation):
    source, root, env = installation
    (root / 'run.sh').write_text('''#!/bin/bash
printf 'run:%s\\n' "$*" >> "$CALLS"
if [[ "$1" == status ]]; then
  if [[ ! -e "$CALLS.first" ]]; then
    touch "$CALLS.first"; printf 'state = running\\n'
  else
    if [[ ! -e "$CALLS.refreshed" ]]; then
      touch "$CALLS.inflight"; sleep 1; touch "$CALLS.refreshed"
    fi
    printf 'Could not find service\\n'; exit 113
  fi
fi
''')
    env.update(TERM='xterm-256color', NO_COLOR='1')
    master, slave = pty.openpty()
    process = subprocess.Popen([BASH, str(source / 'scripts/control.sh')], stdin=slave,
                               stdout=slave, stderr=slave, env=env)
    os.close(slave)
    output = bytearray()
    deadline = time.monotonic() + 18
    sent = False
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.05)[0]:
                output.extend(os.read(master, 65536))
            if Path(env['CALLS'] + '.inflight').exists() and not sent:
                os.write(master, b'1\n')
                sent = True
            if 'ОСТАНОВЛЕН'.encode() in output:
                break
        assert sent and 'ОСТАНОВЛЕН'.encode() in output
        # Allow the menu to consume the key that belonged to its previous view.
        time.sleep(1.5)
        assert 'run:start' not in calls(installation)
        assert 'run:stop' not in calls(installation)
        os.write(master, b'0\n')
        process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)


def test_two_queued_stop_choices_never_restart_the_checker(installation):
    source, root, env = installation
    (root / 'run.sh').write_text('''#!/bin/bash
printf 'run:%s\\n' "$*" >> "$CALLS"
case "$1" in
  status)
    if [[ -e "$CALLS.stopped" ]]; then printf 'Could not find service\\n'; exit 113;
    else printf 'state = running\\n'; fi;;
  stop) touch "$CALLS.stopped";;
  start) touch "$CALLS.restarted";;
esac
''')
    env.update(TERM='xterm-256color', NO_COLOR='1')
    master, slave = pty.openpty()
    process = subprocess.Popen([BASH, str(source / 'scripts/control.sh')], stdin=slave,
                               stdout=slave, stderr=slave, env=env)
    os.close(slave)
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 12
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.05)[0]:
                output.extend(os.read(master, 65536))
            if 'Выберите цифру'.encode() in output and not sent:
                os.write(master, b'1\n1\n')
                sent = True
            if 'ОСТАНОВЛЕН'.encode() in output:
                break
        assert sent and 'ОСТАНОВЛЕН'.encode() in output
        time.sleep(1.5)
        assert calls(installation).count('run:stop') == 1
        assert 'run:start' not in calls(installation)
        os.write(master, b'0\n')
        process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
