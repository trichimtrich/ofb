import idaapi
from PyQt5.Qt import QApplication
import re

NAME_TEMPLATE = '{name}_{offset}'


def _log(fmt, *args):
    print('[OFB] ' + fmt % args)


def _get_base(ea):
    if idaapi.is_debugger_on():
        x = idaapi.modinfo_t()
        _ = idaapi.get_module_info(ea, x)
        base = x.base
    else:
        base = idaapi.get_imagebase()
    return base


class ActionWrap(idaapi.action_handler_t):
    desc = None
    hotkey = None

    def do_register(self):
        self.do_unregister()
        res = idaapi.register_action(idaapi.action_desc_t(self.name, self.desc, self, self.hotkey))
        _log('Register action %s: %s', repr(self.name), res)


    def do_unregister(self):
        stt, _ = idaapi.get_action_state(self.name)
        if stt:
            res = idaapi.unregister_action(self.name)
            _log('Unregister action %s: %s', repr(self.name), res)

    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ActionGetOffset(ActionWrap):
    name = 'get_offset_from_base'
    desc = 'Get offset from base'

    def activate(self, ctx):
        ea = ctx.cur_ea
        # print(hex(ida_kernwin.get_screen_ea()))
        base = _get_base(ea)
        off = ea - base
        _log('EA: %x. Base: %x => Offset: %x', ea, base, off)
        QApplication.clipboard().setText(hex(off))
        _log('Copied offset to clipboard')
        
        return 1
        
        
class ActionJumpOffset(ActionWrap):
    name = 'jump_offset_from_base'
    desc = 'Jump offset from base'
    hotkey = 'shift+G'

    def activate(self, ctx):
        ea = ctx.cur_ea
        base = _get_base(ea)
        off = idaapi.ask_addr(0, 'New offset')
        if off is None:
            return 1

        new_ea = base + off
        _log('Base: %x. New offset: %x => New addr: %x', base, off, new_ea)
        if not idaapi.jumpto(new_ea):
            idaapi.warning('Invalid offset to jump from base')

        return 1
        

class ActionRenameOffset(ActionWrap):
    name = 'rename_offset_from_base'
    desc = 'Rename offset from base'
    hotkey = 'shift+N'

    def __init__(self, template):
        super(ActionRenameOffset, self).__init__()

        # precheck template
        try:
            template.format(name='a', offset='1234')
            if template.count('{name}') != 1:
                raise Exception()
        except:
            idaapi.warning('Invalid name template {}, set to default'.format(repr(template)))
            template = '{name}_{offset}'

        self.template = template

        pattern = '^' + template + '$'
        pattern = pattern.replace('{name}', '(.+?)')
        pattern = pattern.replace('{offset}', '[a-z0-9]+')
        self.pattern = re.compile(pattern)


    def activate(self, ctx):
        ea = ctx.cur_ea
        cur_name = idaapi.get_name(ea)
        real_cur_name = None
        if cur_name:
            m = self.pattern.match(cur_name)
            if m:
                real_cur_name = m.group(1)
            else:
                real_cur_name = cur_name
        
        if real_cur_name is None:
            real_cur_name = ''

        real_new_name = idaapi.ask_str(real_cur_name, 0, self.template)
        if real_new_name and real_new_name != real_cur_name:
            base = _get_base(ea)
            off = ea - base
            new_name = self.template.format(
                name=real_new_name, 
                offset='%x' % off,
            )
            if not idaapi.set_name(ea, new_name):
                _log('Set name failed at %x : %s', ea, new_name)
    
        return 1
    

class OFBHook(idaapi.UI_Hooks):
    def __init__(self, *args):
        super(OFBHook, self).__init__(*args)
        self.actions = []


    def register_action(self, a):
        self.actions.append(a)
        a.do_register()


    def finish_populating_widget_popup(self, form, popup):
        if idaapi.get_widget_type(form) in (idaapi.BWN_DISASM, idaapi.BWN_DUMP, idaapi.BWN_PSEUDOCODE ):
            for a in self.actions:
                idaapi.attach_action_to_popup(form, popup, a.name, 'Hoho')

    def fini(self):
        for a in self.actions:
            a.do_unregister()


class OFB(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = 'OFB'
    help = ''
    wanted_name = 'OFB'
    wanted_hotkey = ''

    
    def init(self):
        ui_hook = OFBHook()
        ui_hook.register_action(ActionGetOffset())
        ui_hook.register_action(ActionJumpOffset())
        ui_hook.register_action(ActionRenameOffset(NAME_TEMPLATE))

        _log('UI Hook: %s', ui_hook.hook())
        self.ui_hook = ui_hook
        return idaapi.PLUGIN_KEEP

        
    def run(self, *argv, **kargv):
        pass

        
    def term(self):
        if hasattr(self, 'ui_hook'):
            _log('Unhook UI: %s', self.ui_hook.unhook())
            self.ui_hook.fini()
        

def PLUGIN_ENTRY():
    return OFB()
