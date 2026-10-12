BLOOD = (0x8B, 0x00, 0x00)
STEEL = (0x8C, 0x9C, 0xA8)
BONE = (0xE8, 0xDC, 0xC4)
VOID = (0x0C, 0x0C, 0x0E)

HEX = {
    "blood": "#8b0000",
    "steel": "#8c9ca8",
    "bone": "#e8dcc4",
    "void": "#0c0c0e",
}

RGB = {
    "blood": BLOOD,
    "steel": STEEL,
    "bone": BONE,
    "void": VOID,
}

STATUS_COLOR = {
    "intact": "steel",
    "scored": "bone",
    "broken": "blood",
    "unknown": "bone",
}
