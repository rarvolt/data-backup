import argparse
import getpass
import os
import shutil
import struct
import time
from collections import namedtuple
from pathlib import Path
from typing import Optional

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from humanize import naturalsize
from paramiko import SSHClient, RSAKey, SFTPClient, AutoAddPolicy, PasswordRequiredException


class CloudBackup:
    Copt = namedtuple('Copt', ['format', 'ext'])

    PREFIX = 'cbk'
    TMP_DIR = f'.tmp_{PREFIX}'

    COMPRESS_MAP = {
        'off': Copt('tar', '.tar'),
        'gz': Copt('gztar', '.tar.gz'),
        'bz2': Copt('bztar', '.tar.bz2'),
        'xz': Copt('xztar', '.tar.xz')
    }

    ACTION_MAP = {
        'backup': 'action_backup',
        'restore': 'action_restore',
        'list': 'action_list',
        'search': 'action_search',
    }

    def __init__(self, server: str, ssh_key_path: str, port: int = None,
                 user: str = None,
                 compress: str = 'off', enc_data: Optional[str] = None):
        self.server = server
        self.port = 22 if port is None else port
        self.user = getpass.getuser() if user is None else user
        self.compress = self.COMPRESS_MAP[compress]
        self.ssh_key_path = Path(ssh_key_path)
        self.enc_data = enc_data

        self.tmp_dir: Optional[Path] = None
        self.ssh: Optional[SSHClient] = None
        self.sftp: Optional[SFTPClient] = None

    def run(self, action: str, file_name: str):
        self.__getattribute__(self.ACTION_MAP[action])(file_name)

    def action_backup(self, source: str):
        source = Path(source).absolute()

        print(f"Packing file {source.name} ...")
        packed_source = self._pack_data(source)
        print(f"Encrypting file {packed_source.name} ...")
        enc_key = self._get_enc_key(self.enc_data)
        encrypted_source = self._encrypt_data(packed_source, enc_key)
        print(f"Connecting to {self.user}@{self.server}:{self.port} ...")
        self._ssh_connect(self.ssh_key_path)
        print(f"Sending file {encrypted_source.name} ...")
        self._send_file(encrypted_source)
        print(f"Cleanup ...")
        self._cleanup()

    def action_restore(self, source: str):
        pass

    def action_list(self, source: str):
        pass

    def action_search(self, source: str):
        pass

    def _pack_data(self, source: Path) -> Path:
        if not source.exists():
            raise FileNotFoundError(f"File/dir '{source.as_posix()}' not found")

        if source.is_file() and '.tar' in source.name:
            return source

        self.tmp_dir = source.parent / self.TMP_DIR
        if source.is_file():
            source_dir = self.tmp_dir / source.stem
            os.makedirs(source_dir.as_posix(), exist_ok=True)
            os.link(source.as_posix(), (source_dir / source.name).as_posix())
        elif source.is_dir():
            source_dir = source
        else:
            raise RuntimeError("Unknown data type")

        tar_base = self.tmp_dir / source.stem
        shutil.make_archive(
            base_name=tar_base,
            format=self.compress.format,
            root_dir=source_dir.as_posix(),
        )

        tar_file = tar_base.with_suffix(tar_base.suffix + self.compress.ext)
        return tar_file

    def _get_enc_key(self, enc_data: Optional[str]) -> bytes:
        if enc_data is None:
            return getpass.getpass('Enter encryption key: ').encode()

        enc_path = Path(enc_data)
        if enc_path.exists():
            with open(enc_path.as_posix(), 'r') as enc_file:
                return enc_file.read().encode()
        return enc_data.encode()

    def _encrypt_data(self, source: Path, key_data: bytes,
                      chunk_size_kb: int = 64) -> Path:
        chunk_size = chunk_size_kb * 1024
        out_filename = Path(source.as_posix() + '.enc')
        key = SHA256.new(key_data).digest()
        iv = Random.get_random_bytes(16)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        file_size = os.path.getsize(source.as_posix())

        with open(source.as_posix(), 'rb') as infile:
            with open(out_filename.as_posix(), 'wb') as outfile:
                outfile.write(struct.pack('<Q', file_size))
                outfile.write(iv)

                while True:
                    chunk = infile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)

                    outfile.write(encryptor.encrypt(chunk))

        return out_filename

    def _decrypt_data(self, source: Path, key_data: bytes,
                      chunk_size_kb: int = 24) -> Path:
        chunk_size = chunk_size_kb * 1024
        out_filename = source.with_suffix('')
        key = SHA256.new(key_data).digest()

        with open(source.as_posix(), 'rb') as infile:
            orig_size = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)

            with open(out_filename.as_posix(), 'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))

                outfile.truncate(orig_size)

        return out_filename

    def _send_file(self, source: Path):
        send_start_time = None

        def _put_callback(sent, total):
            nonlocal send_start_time
            speed = sent / (time.time() - send_start_time)
            sent_hum = naturalsize(sent, binary=True)
            total_hum = naturalsize(total, binary=True)
            speed_hum = naturalsize(speed, binary=True)
            print(f"\rSending... {sent_hum} of {total_hum}, {speed_hum}/s     ",
                  end='')

        if self.ssh is None:
            raise ConnectionError("SSH is not connected")

        self.sftp: SFTPClient = self.ssh.open_sftp()
        dirs = self.sftp.listdir()
        if self.PREFIX not in dirs:
            self.sftp.mkdir(self.PREFIX)
        remote_file = Path(self.PREFIX) / source.name
        send_start_time = time.time()
        self.sftp.put(source.as_posix(), remote_file.as_posix(),
                      _put_callback)

    def _ssh_connect(self, key_file: Path):
        self.ssh = SSHClient()
        self.ssh.load_host_keys(os.path.expanduser(
            os.path.join('~', '.ssh', 'known_hosts')))
        self.ssh.set_missing_host_key_policy(AutoAddPolicy())
        try:
            key = RSAKey.from_private_key_file(key_file.as_posix())
        except PasswordRequiredException:
            ssh_pass = getpass.getpass(f"Password for {key_file.as_posix()}: ")
            key = RSAKey.from_private_key_file(key_file.as_posix(), ssh_pass)
        self.ssh.connect(self.server, self.port, self.user, pkey=key)

    def _cleanup(self):
        if self.sftp is not None:
            self.sftp.close()
        if self.ssh is not None:
            self.ssh.close()
        if self.tmp_dir is not None and self.tmp_dir.exists():
            shutil.rmtree(self.tmp_dir.as_posix())

    def exit(self, *args, **kwargs):
        self._cleanup()
        exit(0)


def main():
    p = argparse.ArgumentParser()

    p.add_argument('action',
                   choices=CloudBackup.ACTION_MAP.keys(),
                   help="Action to perform")
    p.add_argument('file_name',
                   help="File name to backup or restore")
    p.add_argument('hostname',
                   help="Remote server address")
    p.add_argument('-u', '--user',
                   required=False,
                   help="Remote server SSH user name")
    p.add_argument('-p', '--port',
                   required=False,
                   type=int,
                   help="Remote server SSH port")
    p.add_argument('-k', '--privkey',
                   required=True,
                   help="Path to SSH private key")
    p.add_argument('-e', '--enc_key',
                   required=True,
                   help="Encryption password or path to keyfile")
    p.add_argument('-c', '--compress',
                   default='off',
                   choices=CloudBackup.COMPRESS_MAP.keys(),
                   help="Compression algorithms")

    args = p.parse_args()

    cb = CloudBackup(
        server=args.hostname,
        port=args.port,
        user=args.user,
        compress=args.compress,
        enc_data=args.enc_key,
        ssh_key_path=args.privkey
    )

    cb.run(args.action, args.file_name)


if __name__ == '__main__':
    main()
