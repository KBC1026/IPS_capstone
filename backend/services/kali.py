from __future__ import annotations

import os
import shlex
from datetime import datetime, timezone

import paramiko


class KaliRunner:
    def __init__(self, host: str, port: int, user: str, password: str | None, key_file: str | None, timeout: int, commands: dict[str, str]):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.commands = commands

    @classmethod
    def from_env(cls) -> "KaliRunner":
        return cls(
            host=os.getenv("KALI_HOST", ""),
            port=int(os.getenv("KALI_PORT", "22")),
            user=os.getenv("KALI_USER", "kali"),
            password=os.getenv("KALI_PASSWORD") or None,
            key_file=os.getenv("KALI_KEY_FILE") or None,
            timeout=int(os.getenv("KALI_COMMAND_TIMEOUT", "120")),
            commands={
                "portscan": _script_command(os.getenv("KALI_PORTSCAN_COMMAND", "")),
                "bruteforce": _script_command(os.getenv("KALI_BRUTEFORCE_COMMAND", "")),
                "sqli": _script_command(os.getenv("KALI_SQLI_COMMAND", "")),
            },
        )

    def run(self, scenario: str) -> dict:
        if scenario == "random":
            scenario = "portscan"

        command = self.commands.get(scenario)
        if not command:
            return {"accepted": False, "scenario": scenario, "message": "허용되지 않은 시나리오입니다."}

        if not self.host:
            return {
                "accepted": False,
                "scenario": scenario,
                "message": "KALI_HOST가 설정되지 않아 원격 실행을 시작할 수 없습니다.",
            }

        try:
            output = self._exec(command)
        except Exception as exc:
            return {
                "accepted": False,
                "scenario": scenario,
                "message": f"Kali SSH 실행 실패: {exc}",
            }

        return {
            "accepted": True,
            "scenario": scenario,
            "message": f"{scenario} 시나리오를 Kali 서버에서 실행했습니다.",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "output": output[-4000:],
        }

    def _exec(self, command: str) -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.load_system_host_keys()
        try:
            connect_kwargs = {
                "hostname": self.host,
                "port": self.port,
                "username": self.user,
                "timeout": 10,
                "banner_timeout": 10,
                "auth_timeout": 10,
            }
            if self.key_file:
                connect_kwargs["key_filename"] = self.key_file
            if self.password:
                connect_kwargs["password"] = self.password

            client.connect(**connect_kwargs)
            _, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            exit_code = stdout.channel.recv_exit_status()
            combined = stdout.read().decode("utf-8", "replace") + stderr.read().decode("utf-8", "replace")
            if exit_code != 0:
                raise RuntimeError(f"exit={exit_code}: {combined[-1000:]}")
            return combined
        finally:
            client.close()


def _script_command(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.endswith(".py"):
        return f"python3 {shlex.quote(value)}"
    return value
