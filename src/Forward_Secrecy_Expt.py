from pathlib import Path
from Load_keys import *

# Get the current directory as reference
BASE_DIR = Path(__file__).resolve().parent
RECORDED_SESSION = (BASE_DIR / ".." / "record" / "recorded_session.txt").resolve()


record = ReadRecordedSessionData()
print(record)