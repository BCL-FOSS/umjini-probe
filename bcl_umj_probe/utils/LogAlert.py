import os
import aiofiles
import gzip
import shutil
import datetime
from pathlib import Path
import logging

class LogAlert:
    def __init__(self):
        self.LOG_DIR = Path("/var/log/umj")
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.logger = logging.getLogger(__name__)
        self.LOG_RETENTION_DAYS = 14
        self.LOG_COMPRESSION_DAYS = 7

    async def write_log(self, log_name: str, message: str):
        if os.path.exists(self.LOG_DIR) is False:
            self.LOG_DIR.mkdir(parents=True, exist_ok=True)

        # Log file name data
        now = datetime.datetime.now()
        today_str = now.strftime("%Y-%m-%d")
        log_file = self.LOG_DIR / f"{log_name}_{today_str}.log"

        # Log file entry data
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}\n"

        async with aiofiles.open(log_file, mode="a") as f:
            await f.write(entry)

        await self.manage_log_rotation(log_name)

    async def manage_log_rotation(self, log_name: str):
        now = datetime.datetime.now()
        compress_cutoff = now - datetime.timedelta(days=self.LOG_COMPRESSION_DAYS)
        delete_cutoff = now - datetime.timedelta(days=self.LOG_RETENTION_DAYS)

        for file in self.LOG_DIR.glob(f"{log_name}_*.log*"):
            try:
                stem = file.stem.replace(f"{log_name}_", "")
                date_str = stem.replace(".gz", "")
                file_date = datetime.datetime.strptime(date_str, "%Y-%m-%d")

                if file_date < delete_cutoff:
                    file.unlink(missing_ok=True)
                    continue

                if file_date < compress_cutoff and file.suffix == ".log":
                    gz_file = file.with_suffix(file.suffix + ".gz")
                    await self._compress_file(file, gz_file)

            except Exception:
                continue

    async def _compress_file(self, source: Path, destination: Path):
        try:
            with open(source, "rb") as f_in:
                with gzip.open(destination, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            source.unlink(missing_ok=True)
        except Exception as e:
            self.logger.error(f"Error compressing {source}: {e}")


