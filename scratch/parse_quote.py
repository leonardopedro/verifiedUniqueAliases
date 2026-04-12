import base64
import struct

data = base64.b64decode("/1RDR4AYACIAC7lPHTrqU+yQyMq5C5EBS0bkck26mh8l62ZOywwFPP6hACAJUiT9OGeahjteeVaC7/0t/LD+WQwDihMaQfbqfathSgAAAAAADB86cLDtgXJyMYQBd/OQ4V27lPsAAAABAAsDlYMAACDLqWEMjbuZZ36WNe067kn3blYWct+Bzl9PSxGSOOUY+Q==")

# TPMS_ATTEST
magic = struct.unpack(">I", data[0:4])[0]
type = struct.unpack(">H", data[4:6])[0]
signer_name_size = struct.unpack(">H", data[6:8])[0]
signer_name = data[8:8+signer_name_size]
cursor = 8 + signer_name_size

extra_data_size = struct.unpack(">H", data[cursor:cursor+2])[0]
extra_data = data[cursor+2:cursor+2+extra_data_size]
cursor += 2 + extra_data_size

# ClockInfo
clock = struct.unpack(">Q", data[cursor:cursor+8])[0]
cursor += 8
reset_count = struct.unpack(">I", data[cursor:cursor+4])[0]
cursor += 4
restart_count = struct.unpack(">I", data[cursor:cursor+4])[0]
cursor += 4
safe = data[cursor]
cursor += 1

firmware_version = struct.unpack(">Q", data[cursor:cursor+8])[0]
cursor += 8

# Attested Data (Quote)
pcr_select_count = struct.unpack(">I", data[cursor:cursor+4])[0]
cursor += 4

print(f"Magic: {hex(magic)}")
print(f"Type: {hex(type)}")
print(f"Extra Data (Nonce) Hex: {extra_data.hex()}")
print(f"Extra Data (Nonce) B64: {base64.b64encode(extra_data).decode()}")

# Hash of bound_user_data
expected_nonce = base64.b64decode("CVIk/ThnmoY7XnlWgu/9Lfyw/lkMA4oTGkH26n2rYUo=")
print(f"Expected Nonce Hex: {expected_nonce.hex()}")
