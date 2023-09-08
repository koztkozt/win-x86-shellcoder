#!/usr/bin/python3
import sys
import argparse
import ctypes, struct, numpy
import keystone as ks

def to_hex(s):
    retval = list()
    for char in s:
        retval.append(hex(ord(char)).replace("0x", ""))
    return "".join(retval)

def push_string(input_string):
    rev_hex_payload = str(to_hex(input_string))
    rev_hex_payload_len = len(rev_hex_payload)

    instructions = []
    first_instructions = []
    null_terminated = False

    first_instructions.append("xor eax eax;")

    if((rev_hex_payload_len% 8) == 0):
        first_instructions.append("push eax;")

    for i in range(rev_hex_payload_len, 0, -1):
        # add every 4 byte (8 chars) to one push statement
        if ((i != 0) and ((i % 8) == 0)):
            target_bytes = rev_hex_payload[i-8:i]
            instructions.append(f"push 0x{target_bytes[6:8] + target_bytes[4:6] + target_bytes[2:4] + target_bytes[0:2]};")
        # handle the left ofer instructions
        elif ((0 == i-1) and ((i % 8) != 0) and (rev_hex_payload_len % 8) != 0):
            if (rev_hex_payload_len % 8 == 2):
                first_instructions.append(f"mov al, 0x{rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]};")
                first_instructions.append("push eax;")
            elif (rev_hex_payload_len % 8 == 4):
                target_bytes = rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]
                first_instructions.append(f"mov ax, 0x{target_bytes[2:4] + target_bytes[0:2]};")
                first_instructions.append("push eax;")
            else:
                target_bytes = rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]
                first_instructions.append(f"mov al, 0x{target_bytes[4:6]};")
                first_instructions.append("push eax;")
                first_instructions.append(f"mov ax, 0x{target_bytes[2:4] + target_bytes[0:2]};")
                first_instructions.append("push ax;")
            null_terminated = True

    instructions = first_instructions + instructions
    asm_instructions = "".join(instructions)
    return asm_instructions

def convert_neg(dword):
    return ((-int.from_bytes(dword, "little")) & 0xFFFFFFFF).to_bytes(4, "little")


def push_string2(input_str, bad_chars, end=b"\x00"):
    def gen_push_code(dword):
        if not any(c in bad_chars for c in dword):
            return f'push  {hex(int.from_bytes(dword, "little"))};'

    def gen_neg_code(dword):
        neg_dword = convert_neg(dword)
        if not any(c in bad_chars for c in neg_dword):
            return (
                f'mov   eax, {hex(int.from_bytes(neg_dword, "little"))};'
                f"neg   eax;"
                f"push  eax;"
            )

    def gen_xor_code(dword):
        xor_dword_1 = xor_dword_2 = b""
        for i in range(4):
            for xor_byte_1 in range(256):
                xor_byte_2 = dword[i] ^ xor_byte_1
                if (xor_byte_1 not in bad_chars) and (xor_byte_2 not in bad_chars):
                    xor_dword_1 += bytes([xor_byte_1])
                    xor_dword_2 += bytes([xor_byte_2])
                    break
            else:
                return None

        return (
            f'mov   eax, {hex(int.from_bytes(xor_dword_1, "little"))};'
            f'xor   eax, {hex(int.from_bytes(xor_dword_2, "little"))};'
            f"push  eax;"
        )

    input_bytes = input_str.encode() if type(input_str) is str else input_str
    input_bytes += end

    code = ""
    for i in range(0, len(input_bytes), 4)[::-1]:
        pad_byte = [c for c in range(256) if c not in bad_chars][0]
        dword = input_bytes[i : i + 4]
        dword += bytes([pad_byte]) * (4 - len(dword))

        new_code = gen_push_code(dword)
        if not new_code:
            new_code = gen_neg_code(dword)
        if not new_code:
            new_code = gen_xor_code(dword)
        if not new_code:
            raise Exception(f"cannot push dword: {dword}")
        code += new_code

    return code    
    
if __name__ == "__main__":
    string1 = "Userenv.dll"  
    bad_chars = b"\x00"
    
    print(f"\nlength of {string1}: {len(string1)}\n")
    modified_string  = push_string(string1).replace(";", "\n")
    print(f'Output1:\n{modified_string}')
      
    modified_string  = push_string2(string1, bad_chars).replace(";", "\n")
    print(f'Output2 w/o bad chars:\n{modified_string}')
