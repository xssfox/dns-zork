from __future__ import print_function

import argparse
import sys
import time
import random
import re
from textwrap import wrap
import pickle

try:
    from xyppy.debug import err
except ImportError:
    print('error: must either build xyppy into a standalone file, or run xyppy as a module, e.g. "python -m xyppy"')
    sys.exit(1)

from xyppy.zenv import Env, step
import xyppy.blorb as blorb
import xyppy.ops as ops
import xyppy.six.moves.urllib as urllib


import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


D = DomainName('zork.host.')
IP = '52.207.173.244'
TTL = 0

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.andrei,  # email of the domain administrator
    times=(
        201307231,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)
ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.mail: [A(IP)],
    D.andrei: [CNAME(D)],
}

games = {}

def dns_response(data):
    try:
        request = DNSRecord.parse(data)

        print(request)

        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        
        qname = request.q.qname
        qn = str(qname)
        qtype = request.q.qtype
        qt = QTYPE[qtype]
        if qtype == TXT:
            subdomains = str(qname).split(".")
            command = subdomains[0].replace("-", " ")
            if len(subdomains) == 5:
                id = subdomains[1]
                if id not in games:
                    games[id] = test()
                text = games[id].next_step(command).strip()
            else:
                text = "example: dig look.{unique-id}.zork.host TXT"
            #text = re.sub(r'\s+', ' ', text)
            for line in text.split("\n"):
                reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=TTL, rdata=TXT(line)))
        if qn == D or qn.endswith('.' + D):

            for name, rrs in records.items():
                if name == qn:
                    for rdata in rrs:
                        rqt = rdata.__class__.__name__
                        if qt in ['*', rqt]:
                            reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))
            
            for rdata in ns_records:
                reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

            reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

        print("---- Reply:\n", reply)

        return reply.pack()
    except:
        pass

class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        try:
            data = self.get_data()
            print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


# so we can hash it
class ScreenLine(object):
    def __init__(self, line):
        self.line = line
        self.inithash = random.randint(0, 0xffffffff)
    def __getitem__(self, idx):
        return self.line[idx]
    def __setitem__(self, idx, val):
        self.line[idx] = val
    def __len__(self):
        return len(self.line)
    def __iter__(self):
        return self.line.__iter__()
    def __hash__(self):
        return self.inithash

def line_empty(line):
    for c in line:
        if c.char != ' ':
            return False
    return True

def is_valid_getch_char(c):
    # TODO: unicode input?
    return (
        c in ['\n', '\t', '\r', '\b', '\x1b'] or
        False or
        (len(c) == 1 and ord(c) > 31 and ord(c) < 127)
    )

def is_valid_inline_char(c):
    # TODO: unicode input?
    return c in ['\n', '\t', '\r', '\b'] or (len(c) == 1 and ord(c) > 31 and ord(c) < 127)


class ScreenChar(object):
    def __init__(self, char, fg_color, bg_color, text_style):
        self.char = char
        self.fg_color = fg_color
        self.bg_color = bg_color
        self.text_style = text_style
    def __str__(self):
        return self.char
    def __eq__(self, sc2):
        return (self.char == sc2.char and
                self.fg_color == sc2.fg_color and
                self.bg_color == sc2.bg_color and
                self.text_style == sc2.text_style)

def sc_line_to_string(line):
    return repr(''.join(map(lambda x: x.char, line)))

class dns_term():
    def __init__(self):
        pass
    # def reset_color(self):
    #     pass
    # def write_char(self, char, fg_col, bg_col):
    #     print(char)
    # def write_char_with_color(self, char, fg_col, bg_col):
    #     print(char)
    def get_size(self):
        return 80, 40
    # def scroll_down(self):
    #     pass
    # def fill_to_eol_with_bg_color(self):
    #     pass
    # def cursor_right(self):
    #     pass
    # def cursor_left(self):
    #     pass
    # def clear_line(self):
    #     pass
    # def hide_cursor(self):
    #     pass
    # def show_cursor(self):
    #     pass
    # def clear_screen(self):
    #     pass
    # def home_cursor(self):
    #     pass
    # def set_color(self):
    #     pass
    def supports_unicode(self):
        return sys.stdout.encoding in ['UTF-8', 'UTF-16', 'UTF-32']
    def getch_or_esc_seq(self):
        return None
    def puts(self,s):
        pass
    def flush(self):
        pass


    class Screen(object):
        def __init__(self, env):
            self.env = env
            self.textBuf = self.make_screen_buf()
            self.seenBuf = {line: True for line in self.textBuf}
            self.wrapBuf = []
            self.haveNotScrolled = True
            self.output  = ""
        def reset_color(self):
            pass
        def write_char(self, char, fg_col, bg_col, style):
            self.output += char
        def write_char_with_color(self, char, fg_col, bg_col):
            self.write_char(char,None, None, None)
        def get_size(self):
            return 80, 40
        def scroll_down(self):
            pass
        def fill_to_eol_with_bg_color(self):
            pass
        def cursor_right(self, a):
            pass
        def cursor_left(self):
            pass
        def clear_line(self):
            pass
        def hide_cursor(self):
            pass
        def show_cursor(self):
            pass
        def cursor_down(self, a):
            pass
        def clear_screen(self):
            pass
        def home_cursor(self):
            pass
        def set_color(self, a, b):
            pass
        def supports_unicode(self):
            return sys.stdout.encoding in ['UTF-8', 'UTF-16', 'UTF-32']
        def getch_or_esc_seq(self):
            return ""
        def puts(self,s):
            pass
        def flush(self):
            pass
        def make_screen_buf(self):
            return [self.make_screen_line() for i in range(self.env.hdr.screen_height_units)]

        def make_screen_line(self):
            c, fg, bg, style = ' ', self.env.fg_color, self.env.bg_color, 'normal'
            return ScreenLine([ScreenChar(c, fg, bg, style) for i in range(self.env.hdr.screen_width_units)])

        def blank_top_win(self):
            env = self.env
            self.home_cursor()
            for i in range(env.top_window_height):
                self.write_char('\n', env.fg_color, env.bg_color, env.text_style)
                self.textBuf[i] = self.make_screen_line()
                self.seenBuf[self.textBuf[i]] = False

        def blank_bottom_win(self):
            for i in range(self.env.top_window_height, self.env.hdr.screen_height_units):
                self.scroll()

        def write(self, text):
            env = self.env

            # the spec suggests pushing the bottom window cursor down.
            # to allow for more trinity box tricks (admittedly only seen so
            # far in baby_tree.zblorb), we'll do that only when it's
            # being written to.
            if env.current_window == 0 and env.cursor[0][0] < env.top_window_height:
                env.cursor[0] = env.top_window_height, env.cursor[0][1]

            as_screenchars = map(lambda c: ScreenChar(c, env.fg_color, env.bg_color, env.text_style), text)
            if env.current_window == 0 and env.use_buffered_output:
                self.write_wrapped(as_screenchars)
            else:
                self.write_unwrapped(as_screenchars)

        # for when it's useful to make a hole in the scroll text
        # e.g. moving already written text around to make room for
        # what's about to become a new split window
        def scroll_top_line_only(self):
            env = self.env
            old_line = self.textBuf[env.top_window_height]

            # avoid some moderately rare shifting text glitches (when possible)
            if self.haveNotScrolled and line_empty(old_line):
                return

            if not self.seenBuf[old_line] and not line_empty(old_line):
                self.pause_scroll_for_user_input()

            self.home_cursor()
            self.overwrite_line_with(old_line)
            self.scroll_down()

            new_line = self.make_screen_line()
            self.textBuf[env.top_window_height] = new_line
            self.seenBuf[new_line] = False

            self.haveNotScrolled = False

        def scroll(self, count_lines=True):
            env = self.env

            if not self.seenBuf[self.textBuf[env.top_window_height]]:
                if not buf_empty(self.textBuf[env.top_window_height:]):
                    self.pause_scroll_for_user_input()

            old_line = self.textBuf.pop(env.top_window_height)

            self.home_cursor()
            self.overwrite_line_with(old_line)
            self.scroll_down()

            new_line = self.make_screen_line()
            self.textBuf.append(new_line)
            self.seenBuf[new_line] = False

            self.haveNotScrolled = False

            self.slow_scroll_effect()

        def update_seen_lines(self):
            self.seenBuf = {line: True for line in self.textBuf}

        def pause_scroll_for_user_input(self):
            # TODO: mark last paused line, set it up so such lines get
            # marked with a plus when still in the buffer, to help your
            # eye track the scroll.
            self.flush()
            if not buf_empty(self.textBuf):
                term_width, term_height = self.get_size()
                if term_width - self.env.hdr.screen_width_units > 0:
                    self.home_cursor()
                    self.cursor_down(term_height-1)
                    # we reserve a one unit right margin for this status char
                    self.cursor_right(self.env.hdr.screen_width_units)
                    self.write_char_with_color('+', self.env.fg_color, self.env.bg_color)
                self.getch_or_esc_seq()
            self.update_seen_lines()

        def overwrite_line_with(self, new_line):
            self.clear_line()
            for c in new_line:
                self.write_char(c.char, c.fg_color, c.bg_color, c.text_style)
            self.fill_to_eol_with_bg_color()

        # TODO: fun but slow, make a config option
        def slow_scroll_effect(self):
            return
            # if not self.env.options.no_slow_scroll:
            #     if not self.is_windows: # windows is slow enough, atm :/
            #         self.flush()
            #         time.sleep(0.002)

        def new_line(self):
            env, win = self.env, self.env.current_window
            row, col = env.cursor[win]
            if win == 0:
                if row+1 == env.hdr.screen_height_units:
                    self.scroll()
                    env.cursor[win] = row, 0
                else:
                    self.slow_scroll_effect()
                    env.cursor[win] = row+1, 0
            else:
                if row+1 < env.top_window_height:
                    env.cursor[win] = row+1, 0
                else:
                    env.cursor[win] = row, col-1 # as suggested by spec

        def write_wrapped(self, text_as_screenchars):
            self.wrapBuf += text_as_screenchars

        # for bg_color propagation (only happens when a newline comes in via wrapping, it seems)
        def new_line_via_spaces(self, fg_color, bg_color, text_style):
            env, win = self.env, self.env.current_window
            row, col = env.cursor[win]
            self.write_unwrapped([ScreenChar(' ', fg_color, bg_color, text_style)])
            while env.cursor[win][1] > col:
                self.write_unwrapped([ScreenChar(' ', fg_color, bg_color, text_style)])

        def finish_wrapping(self):
            env = self.env
            win = env.current_window
            text = self.wrapBuf
            self.wrapBuf = []
            def find_char_or_return_len(cs, c):
                for i in range(len(cs)):
                    if cs[i].char == c:
                        return i
                return len(cs)
            def collapse_on_newline(cs):
                if env.cursor[win][1] == 0:
                    # collapse all spaces
                    while len(cs) > 0 and cs[0].char == ' ':
                        cs = cs[1:]
                    # collapse the first newline (as we just generated one)
                    if len(cs) > 0 and cs[0].char == '\n':
                        cs = cs[1:]
                return cs
            while text:
                if text[0].char == '\n':
                    self.new_line_via_spaces(text[0].fg_color, text[0].bg_color, text[0].text_style)
                    text = text[1:]
                elif text[0].char == ' ':
                    self.write_unwrapped([text[0]])
                    text = text[1:]
                    text = collapse_on_newline(text)
                else:
                    first_space = find_char_or_return_len(text, ' ')
                    first_nl = find_char_or_return_len(text, '\n')
                    word = text[:min(first_space, first_nl)]
                    text = text[min(first_space, first_nl):]
                    if len(word) > env.hdr.screen_width_units:
                        self.write_unwrapped(word)
                    elif env.cursor[win][1] + len(word) > env.hdr.screen_width_units:
                        self.new_line_via_spaces(word[0].fg_color, word[0].bg_color, word[0].text_style)
                        self.write_unwrapped(word)
                    else:
                        self.write_unwrapped(word)
                    text = collapse_on_newline(text)

        def write_unwrapped(self, text_as_screenchars, already_seen=False):
            env = self.env
            win = env.current_window
            w = env.hdr.screen_width_units
            for c in text_as_screenchars:
                if c.char == '\n':
                    self.new_line()
                else:
                    y, x = env.cursor[win]
                    oldc = self.textBuf[y][x]
                    self.textBuf[y][x] = c
                    if c != oldc and not already_seen:
                        self.seenBuf[self.textBuf[y]] = False
                    env.cursor[win] = y, x+1
                    if x+1 == w:
                        self.new_line()

        def flush(self):
            self.finish_wrapping()
            self.home_cursor()
            buf = self.textBuf
            for i in range(len(buf)):
                for j in range(len(buf[i])):
                    c = buf[i][j]
                    self.write_char(c.char, c.fg_color, c.bg_color, c.text_style)
                if i < len(buf) - 1:
                    self.write_char('\n', c.fg_color, c.bg_color, c.text_style)
                else:
                    self.fill_to_eol_with_bg_color()

        def get_line_of_input(self, prompt='', prefilled=''):
            env = self.env
            
            for c in prompt:
                self.write_unwrapped([ScreenChar(c, env.fg_color, env.bg_color, env.text_style)], already_seen=True)
            self.flush()
            self.update_seen_lines()

            row, col = env.cursor[env.current_window]

            self.home_cursor()
            self.cursor_down(row)
            self.cursor_right(col)
            self.set_color(env.fg_color, env.bg_color)
            if line_empty(self.textBuf[row][col:]):
                self.fill_to_eol_with_bg_color()
            self.show_cursor()

            col = max(0, col-len(prefilled)) # TODO: prefilled is a seldom-used old and crusty feature, but make unicode safe
            env.cursor[env.current_window] = row, col

            c = env.command
            if c == None:
                raise ValueError()
            env.command=None
            print(f"blah: {c}")
            return c

        def first_draw(self):
            env = self.env
            for i in range(env.hdr.screen_height_units-1):
                self.write_char('\n', env.fg_color, env.bg_color, env.text_style)
            self.fill_to_eol_with_bg_color()
            self.home_cursor()

        def getch_or_esc_seq(self):
            return None 
            c = "" # TODO
            self.update_seen_lines()
            if c == '\x7f': #delete should be backspace
                c = '\b'
            if not is_valid_getch_char(c):
                return '?'
            return c

        # for save game error messages and such
        # TODO: better formatting here (?)
        def msg(self, text):
            self.write(text)
            self.write('[press any key to continue]\n')
            self.flush()
            self.getch_or_esc_seq()
class test():
    def __init__(self):

        with open("ZORK1.DAT", 'rb') as f:
            mem = f.read()

        if blorb.is_blorb(mem):
            mem = blorb.get_code(mem)
        term = dns_term()
        self.env = Env(mem,term)
        self.env.command = ""
        self.env.screen.first_draw()
        ops.setup_opcodes(self.env)
    def next_step(self, command):
        self.env.command = command
        for x in range(0,10000):
            try:
                step(self.env)
            except ValueError:
                break
        text = ""
        self.env.output_buffer[1].output = ""
        for line in self.env.output_buffer[1].textBuf:
            for screenchar in line.line:
                text += screenchar.char
            text += "\n"
        return text
if __name__ == '__main__':
    # a = test()
    # a.env.command = "look"
    # a.next_step()
    # for line in a.env.output_buffer[1].textBuf:
    #     for screenchar in line.line:
    #         sys.stdout.write(screenchar.char)
    #     sys.stdout.write("\n")
    # a.env.output_buffer[1].output = ""


    # a.env.command = "north"
    # a.next_step()
    # for line in a.env.output_buffer[1].textBuf:
    #     for screenchar in line.line:
    #         sys.stdout.write(screenchar.char)
    #     sys.stdout.write("\n")
    # a.env.output_buffer[1].output = ""



    # b = test()
    # b.env.command = "look"
    # b.next_step()
    # for line in a.env.output_buffer[1].textBuf:
    #     for screenchar in line.line:
    #         sys.stdout.write(screenchar.char)
    #     sys.stdout.write("\n")
    # b.env.output_buffer[1].output = ""


    # b.env.command = "north"
    # b.next_step()
    # for line in a.env.output_buffer[1].textBuf:
    #     for screenchar in line.line:
    #         sys.stdout.write(screenchar.char)
    #     sys.stdout.write("\n")
    # b.env.output_buffer[1].output = ""
    

    servers = []
    servers.append(socketserver.ThreadingUDPServer(('', 54), UDPRequestHandler))
    servers.append(socketserver.ThreadingTCPServer(('', 54), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

