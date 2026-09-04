# app_controller.py

import sys
import tkinter as tk
import parsers
from parsers.parser_tools.gui.inputs_gui import InputsGUI
from parsers.parser_tools.gui.adjust_paths_gui import AdjustPathsGUI
from parsers.parser_tools.gui.outfile_flags_gui import OutfileFlagsGUI
from parsers.parser_tools.gui.load_user_inputs_gui import JsonInputPreviewGUI
from parsers.parser_tools.gui.preflight_gui import RuleBuilderGUI
from parsers.parser_tools.toolbox import GuiWindow, InputDictKeys, InputConfigFlags, InputAdditionalOptions, load_config_user_inputs, check_input_format, dedupe_parser_inputs
from parsers.parser_tools import preflight, parser_logger as logger


class SARPApp:
    
    def __init__(self):
        self._LOADED_PRULES_ONCE = False
        self.parser_inputs = []
        self.parser_outfile = ""
        self.control_flags = {}
        self.additional_options = {}
        self.json_input_preview_gui = None
        self.preflight_rules_path = 'preflight_rules.py'
        self.current_window = GuiWindow.JsonInputPreviewGUI
        self.json_input_preview_gui = JsonInputPreviewGUI(parsers.gui_root)
        self.inputs_gui = InputsGUI(parsers.gui_root)
        self.adjust_paths_gui = AdjustPathsGUI(parsers.gui_root)
        self.outfile_flags_gui = OutfileFlagsGUI(parsers.gui_root)
        self.rulebuildergui = RuleBuilderGUI(parsers.gui_root)
        
        # Set icon
        icon = tk.PhotoImage(file=parsers.LOGO_PATH)
        parsers.gui_root.iconphoto(True, icon)
        
        # GUI feedback loop
        while True:
            match self.current_window:
                # User selects input profile
                case GuiWindow.JsonInputPreviewGUI:
                    # Load inputs if there are any
                    self.json_input_preview_gui.load_view()
                    close_splash()

                    # Load inputs from config file
                    if self.json_input_preview_gui.cleanexit and self.json_input_preview_gui.results is not None:
                        rv = load_config_user_inputs(self.json_input_preview_gui.results)
                        if isinstance(rv, str):
                            if f"Config file {self.json_input_preview_gui.results} not found." != rv:
                                logger.console(f"{rv}\n\nDefaulting to using blank fields.", "Cannot load config", "warning")
                            self.parser_inputs = []
                            self.parser_outfile = ""
                            self.control_flags = {}
                        else:
                            self.parser_inputs, self.parser_outfile, self.control_flags, self.additional_options = rv
                        
                        # Check inputs format
                        if len(self.parser_inputs) > 0:
                            if not check_input_format(self.parser_inputs, self.parser_outfile, self.control_flags):
                                self.json_input_preview_gui.execute_now = False
                        
                        # Dedupe self.parser_inputs
                        self.parser_inputs = dedupe_parser_inputs(self.parser_inputs)
                        
                        # Window finished, set current window to the next window. If executing now, go to default case.
                        if (not (len(self.parser_inputs) <= 0 or len(self.parser_outfile) <= 0 or len(self.control_flags) <= 0)
                            and self.json_input_preview_gui.execute_now
                        ):
                            self.current_window = None
                            # Load prules
                            self.load_prules()
                            self.load_security_prules()
                        else:
                            self.current_window = GuiWindow.InputsGUI
                    # Else exit
                    else:
                        sys.exit(0)
                
                # User passes scanner and path inputs
                case GuiWindow.InputsGUI:
                    self.inputs_gui.load_view(self.parser_inputs)
                    if not self.inputs_gui.cleanexit:
                        sys.exit(0)
                    
                    # Go back if selected
                    if self.inputs_gui.back:
                        self.current_window = GuiWindow.JsonInputPreviewGUI
                    else:
                        self.parser_inputs = self.inputs_gui.results
                        parsers.PROJ_NAME = self.inputs_gui.results_project_name
                        parsers.PROJ_VERSION = self.inputs_gui.results_project_version
                        self.current_window = GuiWindow.AdjustPathsGUI
            
                # User passes remove/prepend paths
                case GuiWindow.AdjustPathsGUI:
                    self.adjust_paths_gui.load_view(self.parser_inputs)
                    if not self.adjust_paths_gui.cleanexit:
                        sys.exit(0)
                    
                    if self.adjust_paths_gui.back:
                        self.current_window = GuiWindow.InputsGUI
                    else:
                        self.parser_inputs = self.adjust_paths_gui.results
                        self.current_window = GuiWindow.OutfileFlagsGUI

                # User chooses outfile location and control flags
                case GuiWindow.OutfileFlagsGUI:
                    self.outfile_flags_gui.load_view(self.parser_outfile, self.control_flags, self.additional_options)
                    if not self.outfile_flags_gui.cleanexit:
                        sys.exit(0)
                    
                    self.parser_outfile = self.outfile_flags_gui.results[InputDictKeys.OUTFILE.value]
                    self.additional_options[InputAdditionalOptions.JOBS.opt] = self.outfile_flags_gui.results[InputAdditionalOptions.JOBS.opt]
                    self.control_flags = {f.flag: self.outfile_flags_gui.results[f.flag]
                                        for f in InputConfigFlags
                                        if GuiWindow.OutfileFlagsGUI in f.module_visibility}
                    
                    # Go back
                    if self.outfile_flags_gui.back:
                        self.current_window = GuiWindow.AdjustPathsGUI
                    else:
                        self.current_window = GuiWindow.RuleBuilderGUI
                
                # Preflight rule builder
                case GuiWindow.RuleBuilderGUI:
                    # If the checkbox was enabled, ask if user wants to edit the preflight rules
                    if self.control_flags[InputConfigFlags.PREFLIGHT_RULES.flag]:
                        # Load prules initially
                        if not self._LOADED_PRULES_ONCE:
                            self.load_prules()
                            self._LOADED_PRULES_ONCE = True

                        self.rulebuildergui.load_view(parsers.prules, self.control_flags)
                        if self.rulebuildergui.cleanexit:
                            parsers.prules = self.rulebuildergui.result
                        else:
                            self.rulebuildergui.destroy_view()
                            sys.exit(0)
                        
                        # Go back
                        if self.rulebuildergui.back:
                            self.current_window = GuiWindow.OutfileFlagsGUI
                        else:
                            if self.rulebuildergui.enable_security_rules is not None:
                                self.control_flags[InputConfigFlags.SECURITY_PREFLIGHT_RULES.flag] = self.rulebuildergui.enable_security_rules
                            else:
                                self.control_flags[InputConfigFlags.SECURITY_PREFLIGHT_RULES.flag] = InputConfigFlags.SECURITY_PREFLIGHT_RULES.default
                            self.rulebuildergui.destroy_view()
                            self.current_window = None
                            self.load_security_prules()
                    else:
                        parsers.prules = []
                        parsers.security_prules = []
                        self.control_flags[InputConfigFlags.SECURITY_PREFLIGHT_RULES.flag] = False
                        self.current_window = None
                # All inputs windows are finished
                case _:
                    self.destroy_gui()
                    break
            # End match
        # End while
    
    
    def load_prules(self):
        # Load preflight rules if true
        if self.control_flags.get(InputConfigFlags.PREFLIGHT_RULES.flag, InputConfigFlags.PREFLIGHT_RULES.default):
            parsers.prules = preflight.load_prules()
        else:
            parsers.prules = []
    
    def load_security_prules(self):
        if self.control_flags.get(InputConfigFlags.SECURITY_PREFLIGHT_RULES.flag, InputConfigFlags.SECURITY_PREFLIGHT_RULES.default):
            parsers.security_prules = preflight.load_prules(parsers.SECURITY_PREFLIGHT_FILE)
        else:
            parsers.security_prules = []

    def destroy_gui(self):
        self.json_input_preview_gui.destroy_view()
        self.inputs_gui.destroy_view()
        self.adjust_paths_gui.destroy_view()
        self.outfile_flags_gui.destroy_view()
        self.rulebuildergui.destroy_view()

        parsers.gui_root.destroy()

def close_splash():
    # Pyinstaller splash screen
    try:
        import pyi_splash
        if pyi_splash.is_alive():
            pyi_splash.close()
    except ImportError:
        pass
