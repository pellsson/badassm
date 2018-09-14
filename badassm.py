#
# A really really really bad assembler that is
# "compatible" with X816. It is really not compatible
# at all. Actually, rather than a X816-compatible
# assembler, it should be consider a 
# "build that smb-disassembly file"-compatible assembler.
#
# Please don't hate me for it. I hacked it together quick
# as fuck be because building SMB with dosbox took ages
# and was annoying me terribly.
#
# It runs eval() on every expression and operand,
# like a million times, so be careful :)
#
# SMB: https://gist.github.com/1wErt3r/4048722
#
# Enjoy. Or don't. Probably don't.
#
import sys
import re
import os
import json

def run_eval(e, env = {}):
	try:
		res = eval(e, { '__builtins__' : None }, env)
	except:
		return None
	return res

def read_file(filename):
	 return [ it.decode('utf-8') for it in open(filename, 'rb').readlines() ]

def read_defines(defs, code):
	for i in range(0, len(code)):
		m = re.match(r'([A-Za-z_][A-Za-z_0-9]*)\s*(\?)?=\s*([^;]+)', code[i])
		if not m:
			continue
		if '?' == m.group(2):
			if m.group(1) not in defs:
				defs[m.group(1)] = m.group(3).strip()
		else:
			defs[m.group(1)] = m.group(3).strip()
		code[i] = ''

def make_opc(v, opr): return { 'opc': v, 'opr': opr }

def error_at(line, msg): raise Exception('Line %d: %s' % (line, msg))

def instruction(nr, pc, op, opr, opr_type):
	size_tbl = { 'N': 1, 'B': 2, 'I': 2, 'Z': 2, 'ZX': 2, 'ZY': 2, 'A': 3, 'AX': 3, 'AY': 3, 'R': 3, 'RX': 2, 'RY': 2 }
	return { 'nr': nr, 'pc': pc, 'opc': op[opr_type], 'opr': opr, 'size': size_tbl[opr_type], 'otype': opr_type }

def is_number(v):
	try:
		base = 10
		if '0x' == v[0:2]:
			base = 16
		elif '0b' == v[0:2]:
			base = 2
		int(v, base)
		return True
	except:
		return False

def parse_expr(defs, e, outer=True):
	unresolved = False
	m = re.findall(r'((?:[<>][^<>])?[%$]?\w[\w0-9]*)', e)
	if m:
		m = [ it for it in m ]
		sorted(m, key = len)
		for it in m:
			hilo = None
			fmt = '%s'
			val = it
			if '<' == it[0] or '>' == it[0]:
				fmt = '(%s&0xff)' if '<' == it[0] else '(%s>>8)'
				val = it[1:]
			if '$' == val[0] or '%' == val[0]:
				val = ('0x' if '$' == val[0] else '0b') + val[1:]
			elif val in defs:
				val = defs[val]
				if outer:
					p = parse_expr(defs, fmt % (val), False)
					if p['unresolved']:
						unresolved = True
					val = p['expanded']
					fmt = '%s'
			elif not is_number(val):
				unresolved = True
			e = e.replace(it, fmt % (val))
	res = 0
	if not unresolved:
		res = run_eval(e, defs)
	return { 'expanded': e, 'unresolved': unresolved, 'res': res }

def parse_int(nr, defs, e, force_byte = False):
	p = parse_expr(defs, e)
	if p['unresolved']:
		error_at(nr, 'Expected an integer')
	if force_byte and p['res'] > 0xff:
		error_at(nr, 'Value does not fit in a byte')
	elif p['res'] > 0xffff:
		error_at(nr, 'Value too big to fit in a word')
	return p['res']

def assemble(code, defs):
	pc = 0
	labels = {}
	table = {
		'adc': { 'I': 0x69, 'Z': 0x65, 'ZX': 0x75, 'A': 0x6D, 'AX': 0x7D, 'AY': 0x79, 'RX': 0x61, 'RY': 0x71 },
		'and': { 'I': 0x29, 'Z': 0x25, 'ZX': 0x35, 'A': 0x2D, 'AX': 0x3D, 'AY': 0x39, 'RX': 0x21, 'RY': 0x31 },
		'asl': { 'N': 0x0A, 'Z': 0x06, 'ZX': 0x16, 'A': 0x0E, 'AX': 0x1E },
		'bcc': { 'B': 0x90 },
		'bcs': { 'B': 0xB0 },
		'beq': { 'B': 0xF0 },
		'bit': { 'Z': 0x24, 'A': 0x2C },
		'bmi': { 'B': 0x30 },
		'bne': { 'B': 0xD0 },
		'bpl': { 'B': 0x10 },
		'brk': { 'N': 0x00 },
		'clc': { 'N': 0x18 },
		'cld': { 'N': 0xD8 },
		'cmp': { 'I': 0xC9, 'Z': 0xC5, 'ZX': 0xD5, 'A': 0xCD, 'AX': 0xDD, 'AY': 0xD9, 'RX': 0xC1, 'RY': 0xD1 },
		'cpx': { 'I': 0xE0, 'Z': 0xE4, 'A': 0xEC },
		'cpy': { 'I': 0xC0, 'Z': 0xC4, 'A': 0xCC },
		'dec': { 'Z': 0xC6, 'ZX': 0xD6, 'A': 0xCE, 'AX': 0xDE },
		'dex': { 'N': 0xCA },
		'dey': { 'N': 0x88 },
		'eor': { 'I': 0x49, 'Z': 0x45, 'ZX': 0x55, 'A': 0x4D, 'AX': 0x5D, 'AY': 0x59, 'RX': 0x41, 'RY': 0x51 },
		'inc': { 'Z': 0xE6, 'ZX': 0xF6, 'A': 0xEE, 'AX': 0xFE },
		'inx': { 'N': 0xE8 },
		'iny': { 'N': 0xC8 },
		'jmp': { 'A': 0x4C, 'R': 0x6C },
		'jsr': { 'A': 0x20 },
		'lda': { 'I': 0xA9, 'Z': 0xA5, 'ZX': 0xB5, 'A': 0xAD, 'AX': 0xBD, 'AY': 0xB9, 'RX': 0xA1, 'RY': 0xB1 },
		'ldx': { 'I': 0xA2, 'Z': 0xA6, 'ZY': 0xB6, 'A': 0xAE, 'AY': 0xBE },
		'ldy': { 'I': 0xA0, 'Z': 0xA4, 'ZX': 0xB4, 'A': 0xAC, 'AX': 0xBC },
		'lsr': { 'N': 0x4A, 'Z': 0x46, 'ZX': 0x56, 'A': 0x4E, 'AX': 0x5E },
		'nop': { 'N': 0xEA },
		'ora': { 'I': 0x09, 'Z': 0x05, 'ZX': 0x15, 'A': 0x0D, 'AX': 0x1D, 'AY': 0x19, 'RX': 0x01, 'RY': 0x11 },
		'pha': { 'N': 0x48 },
		'php': { 'N': 0x08 },
		'pla': { 'N': 0x68 },
		'plp': { 'N': 0x28 },
		'rol': { 'N': 0x2A, 'Z': 0x26, 'ZX': 0x36, 'A': 0x2E, 'AX': 0x3E },
		'ror': { 'N': 0x6A, 'Z': 0x66, 'ZX': 0x76, 'A': 0x6E, 'AX': 0x7E },
		'rti': { 'N': 0x40 },
		'rts': { 'N': 0x60 },
		'sbc': { 'I': 0xE9, 'Z': 0xE5, 'ZX': 0xF5, 'A': 0xED, 'AX': 0xFD, 'AY': 0xF9, 'RX': 0xE1, 'RY': 0xF1 },
		'sec': { 'N': 0x38 },
		'sei': { 'N': 0x78 },
		'sta': { 'Z': 0x85, 'ZX': 0x95, 'A': 0x8D, 'AX': 0x9D, 'AY': 0x99, 'RX': 0x81, 'RY': 0x91 },
		'stx': { 'Z': 0x86, 'ZY': 0x96, 'A': 0x8E },
		'sty': { 'Z': 0x84, 'ZX': 0x94, 'A': 0x8C },
		'tax': { 'N': 0xAA },
		'tay': { 'N': 0xA8 },
		'tsx': { 'N': 0xBA },
		'txa': { 'N': 0x8A },
		'txs': { 'N': 0x9A },
		'tya': { 'N': 0x98 },
	}

	_db = { 'I': -1 }
	_dw = { 'A': -2 }

	instr = []
	exclude_lines = False

	for i in range(0, len(code)):
		nr = i + 1
		line = code[i].split(';', 1)[0].strip()
		while True:
			m = re.match(r'(\s*[A-Za-z_][A-Za-z_0-9]*):.*', line)
			if not m:
				break
			lbl = m.group(1).strip()
			if lbl in labels:
				error_at(nr, 'Label %s already defined.' % (lbl))
			labels[lbl] = pc
			line = line[len(m.group(1)) + 1:].strip()
		if not line:
			continue

		if ',' == line[-1]:
			error_at(nr, 'Missing parameter.')
		if '.' == line[0]:
			v = line.split(' ', 1)
			if '.db' == v[0] or '.dw' == v[0]:
				values = v[1].split(',')
				opc = _db if '.db' == v[0] else _dw
				opr_type = 'I' if '.db' == v[0] else 'A'
				for x in values:
					p = parse_expr(defs, x.strip())
					instr.append(instruction(nr, pc, opc, p['expanded'], opr_type))
					pc += (instr[-1]['size'] - 1)
				continue
			elif '.org' == v[0]:
				p = parse_expr(defs, v[1].strip())
				if p['unresolved']:
					error_at(nr, 'Invalid org parameter')
				pc = p['res']
			elif '.if' == v[0]:
				p = parse_expr(defs, v[1])
				if p['unresolved'] or not p['res']:
					exclude_lines = True
			elif '.endif' == v[0]:
				exclude_lines = False
			elif '.index' == v[0] or '.mem' == v[0]:
				if '8' != v[1].strip():
					error_at(nr, 'Only 8-bit memory and operand mode supported.')
			elif '.incbin' == v[0]:
				args = v[1].strip()
				data = open(v[1], 'rb').read()
				for it in data:
					instr.append(instruction(nr, pc, _db, str(it), 'I'))
					pc += 1
			elif '.seekoff' == v[0]:
				args = v[1].split(' ')
				if 2 != len(args):
					error_at(nr, '.seekoff takes exactly two arguments: <absolute_zerobased_offset> <padding_byte>')
				off = parse_int(nr, defs, args[0].strip())
				bv = parse_int(nr, defs, args[1].strip(), True)
				if off < pc:
					error_at(nr, "You can't seek backwards, PC ahead of offset")
				pad_count = (off - pc)
				print("Seek offset - Writing %02X for %d bytes (from pc: %04X)" % (bv, pad_count, pc))
				for i in range(0, pad_count):
					instr.append(instruction(nr, pc, _db, str(bv), 'I'))
					pc += 1
			elif '.vars' == v[0]:
				read_defines(defs, read_file(v[1].strip()))
			else:
				error_at(nr, 'Unsupported directive: "%s"' % (line))
		elif not exclude_lines:
			m = re.match(r'([a-z]+)\s*(.*)?', line)
			if not m:
				error_at(nr, "Was expecting opcode, don't understand")
			mnem = m.group(1)
			if mnem not in table:
				error_at(nr, "Unsupported opcode '%s'" % (mnem))
			opr_type = 'N'
			expr = ''
			if len(m.group(2)):
				opr = [ it.strip() for it in m.group(2).split(',') ]
				if len(opr) > 2:
					error_at(nr, 'Too many operands')
				if '#' == opr[0][0]:
					v = parse_expr(defs, opr[0][1:])
					if v['unresolved'] and v['res'] > 0xff:
						error_at(nr, 'Invalid immediate value.')
					expr = v['expanded']
					opr_type = 'I'
				elif '(' == opr[0][0] and ')' == opr[0][-1]:
					v = parse_expr(defs, opr[0][1:-1])
					opr_type = 'R'
					expr = v['expanded']
				else:
					v = parse_expr(defs, opr[0])
					expr = v['expanded']
					if v['unresolved']:
						opr_type = 'A'
					else:
						if v['res'] > 0xffff:
							error_at(nr, 'Arithmetic overflow!')
						opr_type = 'Z' if v['res'] < 0x100 else 'A'

				if 2 == len(opr):
					if 'x' != opr[1] and 'y' != opr[1]:
						error_at(nr, 'Invalid index register')
					if 'Z' == opr_type or 'A' == opr_type or 'R' == opr_type: 
						opr_type += opr[1].upper()
					else:
						error_at(nr, 'Invalid index operand')
			if mnem in [ 'bcc', 'bcs', 'beq', 'bmi', 'bne', 'bpl' ]:
				if 'A' != opr_type:
					error_at(nr, 'Invalid branch destination.')
				opr_type = 'B' # TODO : check that it was A, else die
			if opr_type not in table[mnem]:
				opr_type = 'AY' if 'ZY' == opr_type else 'ZY'
				if opr_type not in table[mnem]:
					error_at(nr, "Invalid operands for instruction '%s'" % (mnem))
			instr.append(instruction(nr, pc, table[mnem], expr, opr_type))
			pc += instr[-1]['size']
	return instr, labels

def get_byte(nr, e):
	v = int(run_eval(e))
	if None == v:
		return None
	if v > 0xff:
		error_at(nr, 'Value (%d) too large to fit in a byte.' % (v))
	return [ v ]

def get_word(nr, e):
	v = int(run_eval(e))
	if None == v:
		return None
	if v > 0xffff:
		error_at(nr, 'Value (%d) too large to fit in a word.' % (v))
	return [ (v & 0xff), (v >> 8) ]

def build_operand(inst, labels):
	global use_linker
	if 'N' == inst['otype']:
		return []
	p = parse_expr(labels, inst['opr'])
	if p['unresolved']:
		if not use_linker:
			error_at(inst['nr'], 'Unresolved symbol (operand: %s).' % (inst['opr']))
		elif inst['size'] != 3:
			error_at(inst['nr'], 'Relative and RAM symbols must not be undefined (operand: %s).' % (inst['opr']))
		return None
	if 'I' == inst['otype']:
		return get_byte(inst['nr'], p['expanded'])
	elif 'R' == inst['otype'] or 'A' == inst['otype'] or 'AX' == inst['otype'] or 'AY' == inst['otype']:
		return get_word(inst['nr'], p['expanded'])
	elif 'RX' == inst['otype'] or 'RY' == inst['otype']:
		return get_byte(inst['nr'], p['expanded'])
	elif 'Z' == inst['otype'] or 'ZX' == inst['otype'] or 'ZY' == inst['otype']:
		return get_byte(inst['nr'], p['expanded'])
	elif 'B' == inst['otype']:
		v = run_eval(p['expanded'], labels)
		dist = (v - (inst['pc'] + 2))
		if dist < -128 or dist > 127:
			error_at(inst['nr'], 'Branch is too far away.')
		if dist < 0:
			dist = ((dist * -1) ^ 0xFF) + 1
		return [ dist ]
	return []

def build(instr, labels):
	undef = []
	data = []
	for it in instr:
		operand = build_operand(it, labels)
		if None == operand:
			undef.append({ 'off': len(data) + (1 if it['opc'] >= 0 else 0), 'ref': it['opr']})
			operand = [ 0, 0 ]
		if it['opc'] >= 0:
			data += [ it['opc'] ]
		data += operand
	return bytearray(data), undef


if len(sys.argv) < 2:
	print('Usage: %s <infile> [-DDEF=N|--use-linker]' % (sys.argv[0]))

use_linker = False
defs = {}

for i in range(2, len(sys.argv)):
	if '--use-linker' == sys.argv[i]:
		use_linker = True
		print("Assuming a linker will be used, undefined symbols allowed.")
	elif '-D' == sys.argv[i][0:2]:
		d = sys.argv[i][2:].split('=')
		defs[d[0]] = d[1]


code = read_file(sys.argv[1])
print('Assembling: %s (%d lines)' % (sys.argv[1], len(code)))
print('Pass 1')
read_defines(defs, code)
print('Pass 2')
instr, labels = assemble(code, defs)
print('Pass 3')
b, undef = build(instr, labels)

name = os.path.splitext(sys.argv[1])[0]
open(name + '.bin', 'wb').write(b)
open(name + '.map', 'w').write(''.join([ '%s @ %04X\n' % (k, v) for k, v in labels.items() ]))
if len(undef):
	open(name + '.und', 'w').write(json.dumps(undef))

print('Output file: %s (%d bytes)' % (name + '.bin', len(b)))