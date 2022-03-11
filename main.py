import sqlite3
from sqlite3 import Error

from ykman.device import connect_to_device
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import PivSession

# Connect to a YubiKey over a SmartCardConnection, which is needed for PIV.
connection, device, info = connect_to_device(
    connection_types=[SmartCardConnection],  # Possible Connection types to allow
)

with connection:  # This closes the connection after the block
    piv = PivSession(connection)
    attempts = piv.get_pin_attempts()
    print(f"You have {attempts} PIN attempts left.")