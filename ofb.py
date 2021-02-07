import idaapi
from PyQt5.Qt import QApplication

OFB_ACTION_NAME = "get_offset_from_base"

class ActionOFB(idaapi.action_handler_t):
    def activate(self, ctx):
        ea = ctx.cur_ea
        # print(hex(ida_kernwin.get_screen_ea()))
        if idaapi.is_debugger_on():
            x = idaapi.modinfo_t()
            mod = idaapi.get_module_info(ea, x)
            base = x.base
        else:
            base = idaapi.get_imagebase()
        off = ea - base
        print('[O] EA: {}. Base: {} => Offset: {}'.format(hex(ea), hex(base), hex(off)))
        QApplication.clipboard().setText(hex(off))
        print('[O] Copied to clipboard')
        
        return 1
        
        
    def update(self, ctx):
        #print("updating")
        return idaapi.AST_ENABLE_ALWAYS
    

class OFBHook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        if idaapi.get_widget_type(form) in (idaapi.BWN_DISASM, idaapi.BWN_DUMP, idaapi.BWN_PSEUDOCODE ):
            idaapi.attach_action_to_popup(form, popup, OFB_ACTION_NAME, "Hoho")


class OFB(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = 'OFB'
    help = ''
    wanted_name = 'OFB'
    wanted_hotkey = ''

    def _try_clean_action(self):
        stt, _ = idaapi.get_action_state(OFB_ACTION_NAME)
        if stt:
            print('[O] Unregister action: {}'.format(idaapi.unregister_action(ACTION_NAME)))         
    
    
    def init(self):
        self._try_clean_action()
        x = ActionOFB()
        print('[O] Register action: {}'.format(idaapi.register_action(idaapi.action_desc_t(OFB_ACTION_NAME, "Get offset from base", x))))
        ui_hook = OFBHook()
        print('[O] UI Hook: {}'.format(ui_hook.hook()))
        self.ui_hook = ui_hook
        return idaapi.PLUGIN_KEEP
        
    def run(self, *argv, **kargv):
        pass
        
    def term(self):
        if hasattr(self, 'ui_hook'):
            print('[O] Unhook UI: {}'.format(self.ui_hook.unhook()))
        self._try_clean_action()
        

def PLUGIN_ENTRY():
    return OFB()