import logging
import subprocess


class WireGuardCLI:
    logger = logging.getLogger('WireGuard executor')

    @staticmethod
    def ensure_installation() -> bool:
        wg_check = subprocess.run('which wg', shell=True,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        wg_quick_check = subprocess.run(
            'which wg-quick', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        if wg_check.stderr or wg_quick_check.stderr:
            WireGuardCLI.logger.error(
                'WireGuard not found. '
                + 'Ensure that you have both `wg` and `wg-quick` commands installed.')

            return False

        wg_permissions_check = subprocess.run(
            'wg showconf whatever', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        if wg_permissions_check.stderr and wg_permissions_check.stderr.decode('utf8').strip() \
                .endswith('Operation not permitted'):
            WireGuardCLI.logger.error(
                "Can't run WireGuard commands with the current privileges. "
                + "Ensure you've running the command with administrative privileges.")

            return False

        return True

    @staticmethod
    def gen_private_key() -> str:
        result = subprocess.run('wg genkey', shell=True, stdout=subprocess.PIPE)

        return result.stdout.decode('utf8').strip()

    @staticmethod
    def gen_preshared_key() -> str:
        result = subprocess.run('wg genpsk', shell=True, stdout=subprocess.PIPE)

        return result.stdout.decode('utf8').strip()

    @staticmethod
    def get_public_key(private_key: str) -> str:
        result = subprocess.run(f'wg pubkey', shell=True,
                                stdout=subprocess.PIPE, input=private_key.encode('utf8'))

        return result.stdout.decode('utf8').strip()

    @staticmethod
    def up(device_name) -> bool:
        subprocess.run(f'wg-quick down {device_name}', shell=True, stderr=subprocess.DEVNULL)

        result = subprocess.run(f'wg-quick up {device_name}', shell=True)

        if result.returncode:
            WireGuardCLI.logger.error(f'Unable to up device {device_name}')

            return False

        return True

    @staticmethod
    def down(device_name) -> bool:
        result = subprocess.run(f'wg-quick down {device_name}',
                                shell=True, stderr=subprocess.DEVNULL)

        if result.returncode:
            WireGuardCLI.logger.error(f'Unable to down device {device_name}')

            return False

        return True

    def hot_reload(device_name) -> bool:
        result = subprocess.run(
            f'wg syncconf {device_name} <(wg-quick strip {device_name})', shell=True)

        if result.returncode:
            WireGuardCLI.logger.error(f'Unable to hot reload device {device_name}')

            return False

        return True
