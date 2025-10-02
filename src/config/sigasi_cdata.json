# sigasi_cdata.py


# Code: ("Type", CWE)
sigasi_cdata = {
    1: ("Warning", 681),
    2: ("Error", 696),
    3: ("Error", 696),
    4: ("Error", 696),
    5: ("Error", 605), #?
    6: ("Error", 562), #?
    7: ("Error", 710),
    8: ("Warning with Quick Fix", 477), # can be 11047,
    9: ("Error", 710),
    10: ("Error", 710),
    11: ("Error with Quick Fix", 710),
    12: ("Warning", 1041),
    13: ("Warning", 1164), # irrelevant code, case statement explicitly covers all cases, but still contains others case that will never execute. May recommend removing this check, as if the developers remove the 'others' case, they may get hit with a 'Default clause missing from case statement' issue instead. 
    14: ("Error", 705),
    15: ("Error", 710),
    16: ("Error", 710),
    17: ("Error", 710),
    18: ("Error", 710),
    19: ("Error", 710),
    20: ("Warning", 835),
    21: ("Error", 710),
    22: ("Error", 710),
    23: ("Error", 710),
    26: ("Warning", 682), # left argument in range is smaller than right. May be a 682, but a strong case for CWE-670 could be made as well.
    27: ("Error", 710),
    28: ("Error", 710),
    29: ("Error", 710),
    30: ("Error", 710),
    32: ("Error", 710),
    33: ("Error", 710),
    34: ("Error", 710),
    35: ("Error", 99),
    36: ("Error", 710),
    37: ("Info with Quick Fix", 477), # use of obsolete or deprecated package. Could also just be a broad 710.
    38: ("Error", 710), # incorrect adherence to coding conventions with sensitivity lists
    39: ("Error", 710),
    40: ("Error", 708),
    41: ("Error", 710),
    42: ("Error", 710),
    43: ("Error", 710),
    44: ("Error", 710),
    47: ("Info with Quick Fix", 1114), # whitespace issues
    48: ("Error", 710),
    49: ("Warning with Quick Fix", 1164), # including libraries STD or WORK are superfluous, as they're included in all projects by default
    50: ("Warning", 114),
    51: ("Error", 710),
    52: ("Error", 710),
    53: ("Error", 710),
    54: ("Error", 710),
    55: ("Warning", 561),
    57: ("Error", 710),
    58: ("Error", 710),
    64: ("Error", 710),
    67: ("Warning", 561),
    68: ("Warning", 561),
    69: ("Error", 710),
    70: ("Error", 710),
    71: ("Warning", 561), # Dead state in state machine is dealing with dead code, CWE-561. 601 is URL redirection, which doesn't apply
    72: ("Error", 710), # Sensitivity lists should contain all used signals
    73: ("Warning with Quick Fix", 710), # Superfluous signals are valid, and can be done, but are typically not intended    
    76: ("Error", 710),
    79: ("Warning", 561),
    80: ("Warning", 561), # 80 seems to be an error, and may not allow code to compile if found, therefore may not be able to be tied to a CWE.
    81: ("Error", 710),
    82: ("Error", 710),
    83: ("Error", 710),
    84: ("Error", 710),
    85: ("Warning with Quick Fix", 710), # Duplicate signals are valid, and can be done, but are typically not intended
    86: ("Error", 710),
    88: ("Warning", 561),
    89: ("Warning", 563),
    90: ("Warning", 1109),
    91: ("Error", 1270),
    92: ("Info with Quick Fix", 1099), # Checking for inconsistent naming conventions (i.e pTest_Double vs Test_Double_p)
    94: ("Error", 99),
    97: ("Error", 710), # code just has one really long line. CWE710080 may be used, but only if there are too many lines in a given file, not too many characters on a given line.
    99: ("Info with Quick Fix", 1114), # use of tabs may produce inconsistent whitespace style
    144: ("Warning", 118), # Could be CWE71018 or CWE71019. The finding says that 'Sigasi Visual HDL (SVH) checks the vector size in assignments and port maps. This check works at type-time and takes the (symbolic) value of generics into account.'. No reference as to what it's checking for, so 118 seemed generic enough to catch-all.
    163: ("Info with Quick Fix", 1099),
    164: ("Error", 710),
    168: ("Error", 710),
    169: ("Error", 99),
    170: ("Error", 710),
    171: ("Error", 710),
    172: ("Error", 688),
    173: ("Error", 688),
    174: ("Error", 394),
    175: ("Error", 457),
    176: ("Error", 665),
    177: ("Error", 683),
    178: ("Error", 706),
    179: ("Error", 394),
    180: ("Error", 710),
    181: ("Error", 710),
    182: ("Error", 665), #710, 1419, 909
    183: ("Error", 710),
    184: ("Error", 710), #keyword issues would not compile because of keyword errors
    185: ("Warning", 571),
    186: ("Warning", 570),
    187: ("Error", 665), #possibly, technically correct but could not find anything more specific based on criteria
    188: ("Error", 710), #not a compiler error an optional error, is in regards to header comments not following a standard
    189: ("Error", 710), #not a compiler error an optional error, is in regards to files being the same name as design units
    190: ("Warning", 1071),
    191: ("Error", 710),
    192: ("Info with Quick Fix", 1099),
    193: ("Error", 710), #not in vhdl, verilog, or uvm lists
    194: ("Error", 710), #Possible 665 or 400, this sigasi rule is related to concatenating arrays without specified sizes which would result in compiler errors.
    195: ("Error", 710), #not in vhdl, verilog, or uvm lists
    196: ("Error", 710), #not in vhdl, verilog, or uvm lists
    197: ("Error", 664),
    198: ("Error", 1287),
    199: ("Error", 710),
    200: ("Error", 710),
    210: ("Warning", 129),
    211: ("Warning", 129),
    212: ("Error", 710), #vhdl version issue
    213: ("Error", 394),
    214: ("Error", 710), #conditional return statements
    215: ("Error", 710), #if a string is not closed code won't compile
    216: ("Error", 710), #not in vhdl, verilog, or uvm lists
    217: ("Error", 710), #not in vhdl, verilog, or uvm lists
    218: ("Warning", 682), #this is the incorrect calculation, CWE idk if that applies to negative exponents
    219: ("Error", 706),
    220: ("Error", 706),
    221: ("Error", 706),
    222: ("Error", 710), #Library version mismatch
    223: ("Error with Quick Fix", 710), #another vhdl version check
    224: ("Error", 1006),
    225: ("Error", 710), #not in vhdl, verilog, or uvm lists
    226: ("Error with Quick Fix", 1287),
    227: ("Error", 606),
    228: ("Info with Quick Fix", 156), #maybe 1114
    229: ("Warning", 563), ######## do check this as sigasi labels A LOT of things as 229 that aren't 563 
    230: ("Warning", 783),
    231: ("Warning", 758), #or 1006
    232: ("Warning", 697), #maybe 1024
    233: ("Error", 704),
    234: ("Error", 704),
    235: ("Error", 1006), #possible 1052 according to dan 
    236: ("Error", 770),
    251: ("Error with Quick Fix", 1099),
    252: ("Error", 1256),
    253: ("Error", 1109),
    254: ("Error", 1247),


}