# app_controller.py

import sys
import logging
import parsers
from parsers.parser_tools.gui.inputs_gui import InputsGUI, AdjustPathsGUI, OutfileFlagsGUI
from parsers.parser_tools.gui.load_user_inputs_gui import JsonInputPreviewGUI
from parsers.parser_tools.gui.preflight_gui import RuleBuilderGUI
from parsers.parser_tools.toolbox import GuiWindow, InputDictKeys, InputConfigFlags, console, load_config_user_inputs, check_input_format, dedupe_parser_inputs
from parsers.parser_tools import preflight

logger = logging.getLogger(__name__)


class SARPApp:
    
    def __init__(self):
        self.parser_inputs = []
        self.parser_outfile = ""
        self.control_flags = {}
        self.select_input = None
        self.current_window = GuiWindow.JsonInputPreviewGUI
        
        # GUI feedback loop
        while True:
            match self.current_window:
                # User selects input profile
                case GuiWindow.JsonInputPreviewGUI:
                    # Load inputs if there are any
                    self.select_input = JsonInputPreviewGUI(parsers.gui_root)
                    self.close_splash()
                    parsers.gui_root.wait_window(self.select_input.root)

                    # Load inputs from config file
                    if self.select_input.cleanexit and self.select_input.results is not None:
                        rv = load_config_user_inputs(self.select_input.results)
                        if isinstance(rv, str):
                            if f"Config file {self.select_input.results} not found." != rv:
                                console(f"{rv}\n\nDefaulting to using blank fields.", "Cannot load config", "warning", orig_name=__name__)
                            self.parser_inputs = []
                            self.parser_outfile = ""
                            self.control_flags = {}
                        else:
                            self.parser_inputs, self.parser_outfile, self.control_flags = rv
                        
                        # Check inputs format
                        if len(self.parser_inputs) > 0:
                            if not check_input_format(self.parser_inputs, self.parser_outfile, self.control_flags):
                                self.select_input.execute_now = False
                        
                        # Dedupe self.parser_inputs
                        self.parser_inputs = dedupe_parser_inputs(self.parser_inputs)
                        
                        # Window finished, set current window to the next window. If executing now, go to default case.
                        if (not (len(self.parser_inputs) <= 0 or len(self.parser_outfile) <= 0 or len(self.control_flags) <= 0)
                            and self.select_input.execute_now
                        ):
                            self.current_window = None
                        else:
                            self.current_window = GuiWindow.InputsGUI
                    # Else exit
                    else:
                        sys.exit(0)
                
                # User passes scanner and path inputs
                case GuiWindow.InputsGUI:
                    inputs_gui = InputsGUI(parsers.gui_root, self.parser_inputs)
                    if not inputs_gui.cleanexit:
                        sys.exit(0)
                    
                    # Go back if selected
                    if inputs_gui.back:
                        self.current_window = GuiWindow.JsonInputPreviewGUI
                    else:
                        self.parser_inputs = inputs_gui.results
                        parsers.PROJ_NAME = inputs_gui.results_project_name
                        parsers.PROJ_VERSION = inputs_gui.results_project_version
                        self.current_window = GuiWindow.AdjustPathsGUI
            
                # User passes remove/prepend paths
                case GuiWindow.AdjustPathsGUI:
                    adjust_paths_gui = AdjustPathsGUI(parsers.gui_root, self.parser_inputs)
                    if not adjust_paths_gui.cleanexit:
                        sys.exit(0)
                    
                    if adjust_paths_gui.back:
                        self.current_window = GuiWindow.InputsGUI
                    else:
                        self.parser_inputs = adjust_paths_gui.results
                        self.current_window = GuiWindow.OutfileFlagsGUI

                # User chooses outfile location and control flags
                case GuiWindow.OutfileFlagsGUI:
                    outfile_flags_gui = OutfileFlagsGUI(parsers.gui_root, self.parser_outfile, self.control_flags)
                    if not outfile_flags_gui.cleanexit:
                        sys.exit(0)
                    
                    self.parser_outfile = outfile_flags_gui.results[InputDictKeys.OUTFILE.value]
                    self.control_flags = {f.flag: outfile_flags_gui.results[f.flag]
                                        for f in InputConfigFlags
                                        if f.module_visibility == GuiWindow.OutfileFlagsGUI}
                    
                    # Go back
                    if outfile_flags_gui.back:
                        self.current_window = GuiWindow.AdjustPathsGUI
                    else:
                        self.current_window = GuiWindow.RuleBuilderGUI
                
                # Preflight rule builder
                case GuiWindow.RuleBuilderGUI:
                    # If the checkbox was enabled, ask if user wants to edit the preflight rules
                    if self.control_flags[InputConfigFlags.PREFLIGHT_RULES.flag]:
                        # Load the preflight rules
                        preflight.load_prules()

                        rulebuildergui = RuleBuilderGUI(parsers.gui_root, parsers.prules, self.control_flags)
                        
                        if rulebuildergui.cleanexit:
                            parsers.prules = rulebuildergui.result
                        else:
                            sys.exit(0)
                        
                        # Go back
                        if rulebuildergui.back:
                            self.current_window = GuiWindow.OutfileFlagsGUI
                        else:
                            if rulebuildergui.enable_default_rules is not None:
                                self.control_flags[InputConfigFlags.DEFAULT_PREFLIGHT_RULES.flag] = rulebuildergui.enable_default_rules
                            else:
                                self.control_flags[InputConfigFlags.DEFAULT_PREFLIGHT_RULES.flag] = InputConfigFlags.DEFAULT_PREFLIGHT_RULES.default
                            self.current_window = None
                    else:
                        parsers.prules = []
                        self.control_flags[InputConfigFlags.DEFAULT_PREFLIGHT_RULES.flag] = InputConfigFlags.DEFAULT_PREFLIGHT_RULES.default
                        self.current_window = None
                # All inputs windows are finished
                case _:
                    break
            # End match
        # End while

    def close_splash(self):
        # Pyinstaller splash screen
        try:
            import pyi_splash
            pyi_splash.close()
        except ImportError:
            pass
