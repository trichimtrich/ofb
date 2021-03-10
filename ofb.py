import idaapi
from PyQt5.Qt import QApplication


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
        print('[O] Register action: {}'.format(idaapi.register_action(idaapi.action_desc_t(self.name, self.desc, self, self.hotkey))))


    def do_unregister(self):
        stt, _ = idaapi.get_action_state(self.name)
        if stt:
            print('[O] Unregister action: {}'.format(idaapi.unregister_action(self.name)))  

class ActionOFB1(ActionWrap):
    name = "get_offset_from_base"
    desc = "Get offset from base"

    def activate(self, ctx):
        ea = ctx.cur_ea
        # print(hex(ida_kernwin.get_screen_ea()))
        base = _get_base(ea)
        off = ea - base
        print('[O] EA: {}. Base: {} => Offset: {}'.format(hex(ea), hex(base), hex(off)))
        QApplication.clipboard().setText(hex(off))
        print('[O] Copied to clipboard')
        
        return 1
        
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    

class ActionOFB2(ActionWrap):
    name = "jump_offset_from_base"
    desc = "Jump offset from base"
    hotkey = "shift+G"

    def activate(self, ctx):
        base = _get_base(ctx.cur_ea)
        off = idaapi.ask_addr(0, 'New offset')
        if off is None:
            return 1

        new_ea = base + off
        print('[O] Base: {}. New offset: {} => New addr: {}'.format(hex(base), hex(off), hex(new_ea)))
        if not idaapi.jumpto(new_ea):
            idaapi.warning('Invalid offset to jump from base')

        return 1
        
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


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
                idaapi.attach_action_to_popup(form, popup, a.name, "Hoho")

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
        ui_hook.register_action(ActionOFB1())
        ui_hook.register_action(ActionOFB2())

        print('[O] UI Hook: {}'.format(ui_hook.hook()))
        self.ui_hook = ui_hook
        return idaapi.PLUGIN_KEEP

        
    def run(self, *argv, **kargv):
        pass
        
    def term(self):
        if hasattr(self, 'ui_hook'):
            print('[O] Unhook UI: {}'.format(self.ui_hook.unhook()))
            self.ui_hook.fini()
        

def PLUGIN_ENTRY():
    return OFB()
