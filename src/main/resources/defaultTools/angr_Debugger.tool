<?xml version="1.0" encoding="UTF-8"?>
<TOOL_CONFIG CONFIG_NAME="NO_LONGER_USED">
    <SUPPORTED_DATA_TYPE CLASS_NAME="ghidra.program.model.dtarchive.ProjectDataTypeArchive" />
    <SUPPORTED_DATA_TYPE CLASS_NAME="ghidra.program.model.listing.Program" />
    <ICON LOCATION="images/angr-debugger.png" />
    <TOOL TOOL_NAME="angr Debugger" INSTANCE_NAME="">
        <OPTIONS>
            <CATEGORY NAME="Key Bindings">
                <WRAPPED_OPTION NAME="angr Toggle Breakpoint (AngrDebuggerPlugin)" CLASS="ghidra.framework.options.WrappedActionTrigger" LAST_REGISTERED="2026-11-14">
                    <STATE NAME="KeyStroke" TYPE="string" VALUE="pressed K" />
                    <STATE NAME="MouseBinding" TYPE="string" VALUE="" />
                </WRAPPED_OPTION>
            </CATEGORY>
        </OPTIONS>
        <PACKAGE NAME="angr Debugger" />
        <PACKAGE NAME="Ghidra Core">
            <INCLUDE CLASS="ghidra.app.plugin.core.interpreter.InterpreterPanelPlugin" />
        </PACKAGE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin">
            <STATE NAME="CASE_SENSITIVE" TYPE="boolean" VALUE="false" />
            <ARRAY NAME="GO_TO_HISTORY" TYPE="string" />
            <STATE NAME="INCLUDE_DYNAMIC" TYPE="boolean" VALUE="true" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.functionwindow.FunctionWindowPlugin">
            <STATE NAME="NAVIGATE_ON_INCOMING_EVENT" TYPE="boolean" VALUE="false" />
            <STATE NAME="NAVIGATE_ON_OUTGOING_EVENT" TYPE="boolean" VALUE="true" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.datapreview.DataTypePreviewPlugin">
            <STATE NAME="TerminatedCString" TYPE="string" VALUE="/" />
            <STATE NAME="TerminatedUnicode" TYPE="string" VALUE="/" />
            <STATE NAME="byte" TYPE="string" VALUE="/" />
            <STATE NAME="char" TYPE="string" VALUE="/" />
            <STATE NAME="double" TYPE="string" VALUE="/" />
            <STATE NAME="dword" TYPE="string" VALUE="/" />
            <STATE NAME="float" TYPE="string" VALUE="/" />
            <STATE NAME="qword" TYPE="string" VALUE="/" />
            <STATE NAME="word" TYPE="string" VALUE="/" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.features.base.memsearch.gui.MemorySearchPlugin">
            <STATE NAME="Show Options Panel" TYPE="boolean" VALUE="false" />
            <STATE NAME="Show Scan Panel" TYPE="boolean" VALUE="false" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.overview.OverviewColorPlugin">
            <ARRAY NAME="ActiveServices" TYPE="string" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.symboltree.SymbolTreePlugin">
            <STATE NAME="Include Functions" TYPE="boolean" VALUE="true" />
            <STATE NAME="Include Labels" TYPE="boolean" VALUE="true" />
            <STATE NAME="NAVIGATE_INCOMING" TYPE="boolean" VALUE="false" />
            <STATE NAME="NAVIGATE_OUTGOING" TYPE="boolean" VALUE="true" />
            <STATE NAME="Show Exports" TYPE="boolean" VALUE="true" />
            <STATE NAME="Show Globals" TYPE="boolean" VALUE="true" />
            <STATE NAME="Show Imports" TYPE="boolean" VALUE="true" />
            <STATE NAME="Show Namespaces" TYPE="boolean" VALUE="true" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.calltree.CallTreePlugin">
            <STATE NAME="FILTER_DUPLICATES" TYPE="boolean" VALUE="true" />
            <STATE NAME="FILTER_REFERENCES" TYPE="boolean" VALUE="false" />
            <STATE NAME="FILTER_THUNKS" TYPE="boolean" VALUE="false" />
            <STATE NAME="RECURSE_DEPTH" TYPE="int" VALUE="5" />
            <STATE NAME="SHOW_NAMESPACE" TYPE="boolean" VALUE="false" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="functioncalls.plugin.FunctionCallGraphPlugin">
            <STATE NAME="DISPLAY_SATELLITE" TYPE="boolean" VALUE="true" />
            <STATE NAME="DOCK_SATELLITE" TYPE="boolean" VALUE="true" />
            <STATE NAME="DOCK_SATELLITE_POSITION" TYPE="string" VALUE="LOWER_RIGHT" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="datagraph.DataGraphPlugin">
            <STATE NAME="Compact Format" TYPE="boolean" VALUE="true" />
            <STATE NAME="Navigate In" TYPE="boolean" VALUE="false" />
            <STATE NAME="Navigate Out" TYPE="boolean" VALUE="true" />
            <STATE NAME="Show Popups" TYPE="boolean" VALUE="true" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.symtable.SymbolTablePlugin">
            <XML NAME="FILTER_SETTINGS">
                <SYMBOL_TABLE_FILTER>
                    <ADVANCED_FILTER NAME="Primary Labels" ACTIVE="false">
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                    </ADVANCED_FILTER>
                    <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                    <FILTER NAME="Namespaces" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <ADVANCED_FILTER NAME="Offcut Labels" ACTIVE="false">
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                    </ADVANCED_FILTER>
                    <FILTER NAME="Default (Functions)" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="false" />
                    <FILTER NAME="Imported" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <ADVANCED_FILTER NAME="Non-Primary Labels" ACTIVE="false">
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                    </ADVANCED_FILTER>
                    <ADVANCED_FILTER NAME="Externals" ACTIVE="false">
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Classes" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Local Variables" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Parameters" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Namespaces" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    </ADVANCED_FILTER>
                    <ADVANCED_FILTER NAME="Non-Externals" ACTIVE="false">
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Classes" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Local Variables" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Parameters" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Namespaces" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    </ADVANCED_FILTER>
                    <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                    <FILTER NAME="External Library" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <FILTER NAME="User Defined" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <ADVANCED_FILTER NAME="Stack Variables" ACTIVE="false">
                        <FILTER NAME="Parameters" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Local Variables" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    </ADVANCED_FILTER>
                    <FILTER NAME="Default (Labels)" ACTIVE="false" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="false" />
                    <ADVANCED_FILTER NAME="Not In Memory" ACTIVE="false">
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                    </ADVANCED_FILTER>
                    <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                    <FILTER NAME="Classes" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <ADVANCED_FILTER NAME="Globals" ACTIVE="false">
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Classes" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Namespaces" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    </ADVANCED_FILTER>
                    <FILTER NAME="Parameters" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <FILTER NAME="AI" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <ADVANCED_FILTER NAME="Register Variables" ACTIVE="false">
                        <FILTER NAME="Parameters" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Local Variables" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    </ADVANCED_FILTER>
                    <FILTER NAME="Global Register Variables" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <ADVANCED_FILTER NAME="Locals" ACTIVE="false">
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Classes" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                        <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Namespaces" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    </ADVANCED_FILTER>
                    <ADVANCED_FILTER NAME="Subroutines" ACTIVE="false">
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                    </ADVANCED_FILTER>
                    <FILTER NAME="Analysis" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <FILTER NAME="Local Variables" ACTIVE="false" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="false" />
                    <ADVANCED_FILTER NAME="Entry Points" ACTIVE="false">
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                    </ADVANCED_FILTER>
                    <ADVANCED_FILTER NAME="Unreferenced" ACTIVE="false">
                        <FILTER NAME="Instruction Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Data Labels" ACTIVE="true" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="true" />
                        <FILTER NAME="Function Labels" ACTIVE="true" INCLUDES_DEFAULTS="false" ONLY_CODE_SYMBOLS="true" />
                    </ADVANCED_FILTER>
                </SYMBOL_TABLE_FILTER>
            </XML>
            <STATE NAME="NAVIGATE_ON_INCOMING_EVENT" TYPE="boolean" VALUE="false" />
            <STATE NAME="NAVIGATE_ON_OUTGOING_EVENT" TYPE="boolean" VALUE="true" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin">
            <ARRAY NAME="ArchiveNames" TYPE="string" />
            <STATE NAME="ConflictResolutionMode" TYPE="string" VALUE="RENAME_AND_ADD" />
            <SAVE_STATE NAME="DATA_TYPES_FILTER" KEY="DATA_TYPES_FILTER" TYPE="SaveState">
                <SAVE_STATE NAME="Arrays" KEY="Arrays" TYPE="SaveState">
                    <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="false" />
                    <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                </SAVE_STATE>
                <SAVE_STATE NAME="Enums" KEY="Enums" TYPE="SaveState">
                    <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                    <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                </SAVE_STATE>
                <SAVE_STATE NAME="Functions" KEY="Functions" TYPE="SaveState">
                    <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                    <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                </SAVE_STATE>
                <SAVE_STATE NAME="Other" KEY="Other" TYPE="SaveState">
                    <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                    <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                </SAVE_STATE>
                <SAVE_STATE NAME="Pointers" KEY="Pointers" TYPE="SaveState">
                    <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="false" />
                    <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                </SAVE_STATE>
                <SAVE_STATE NAME="Structures" KEY="Structures" TYPE="SaveState">
                    <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                    <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                </SAVE_STATE>
                <SAVE_STATE NAME="Unions" KEY="Unions" TYPE="SaveState">
                    <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                    <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                </SAVE_STATE>
            </SAVE_STATE>
            <SAVE_STATE NAME="UNNAMED" KEY="DATA_TYPES_TABLE" TYPE="SaveState">
                <SAVE_STATE NAME="DATA_TYPES_FILTER" KEY="DATA_TYPES_FILTER" TYPE="SaveState">
                    <SAVE_STATE NAME="Arrays" KEY="Arrays" TYPE="SaveState">
                        <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="false" />
                        <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                    </SAVE_STATE>
                    <SAVE_STATE NAME="Enums" KEY="Enums" TYPE="SaveState">
                        <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                        <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                    </SAVE_STATE>
                    <SAVE_STATE NAME="Functions" KEY="Functions" TYPE="SaveState">
                        <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                        <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                    </SAVE_STATE>
                    <SAVE_STATE NAME="Other" KEY="Other" TYPE="SaveState">
                        <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                        <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                    </SAVE_STATE>
                    <SAVE_STATE NAME="Pointers" KEY="Pointers" TYPE="SaveState">
                        <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="false" />
                        <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                    </SAVE_STATE>
                    <SAVE_STATE NAME="Structures" KEY="Structures" TYPE="SaveState">
                        <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                        <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                    </SAVE_STATE>
                    <SAVE_STATE NAME="Unions" KEY="Unions" TYPE="SaveState">
                        <STATE NAME="IS_TYPE_ACTIVE" TYPE="boolean" VALUE="true" />
                        <STATE NAME="IS_TYPE_DEF_ACTIVE" TYPE="boolean" VALUE="true" />
                    </SAVE_STATE>
                </SAVE_STATE>
                <STATE NAME="SHOW_ONLY_PROGRAM_TYPES" TYPE="boolean" VALUE="false" />
            </SAVE_STATE>
            <STATE NAME="DataMembersInSearchState" TYPE="boolean" VALUE="false" />
            <ARRAY NAME="Favorite Dts" TYPE="string">
                <A VALUE="/pointer" />
                <A VALUE="/char" />
                <A VALUE="/string" />
                <A VALUE="/TerminatedCString" />
                <A VALUE="/TerminatedUnicode" />
                <A VALUE="/float" />
                <A VALUE="/double" />
                <A VALUE="/longdouble" />
                <A VALUE="/int" />
                <A VALUE="/long" />
                <A VALUE="/uint" />
                <A VALUE="/ulong" />
                <A VALUE="/byte" />
                <A VALUE="/word" />
                <A VALUE="/dword" />
                <A VALUE="/qword" />
            </ARRAY>
            <STATE NAME="PreviewWindowState" TYPE="boolean" VALUE="false" />
            <ARRAY NAME="RecentArchiveNames" TYPE="string" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.script.GhidraScriptMgrPlugin">
            <ARRAY NAME="BundleHost_ACTIVE" TYPE="boolean">
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
                <A VALUE="false" />
            </ARRAY>
            <ARRAY NAME="BundleHost_ENABLE" TYPE="boolean">
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
            </ARRAY>
            <ARRAY NAME="BundleHost_FILE" TYPE="string">
                <A VALUE="$GHIDRA_HOME/Features/PyGhidra/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/SystemEmulation/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Debug/Debugger-rmi-trace/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/FunctionID/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/Swift/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/Decompiler/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Debug/Debugger/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Processors/8051/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/BytePatterns/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/FileFormats/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/BSim/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/WildcardAssembler/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Processors/JVM/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Processors/DATA/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/VersionTracking/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/GnuDemangler/ghidra_scripts" />
                <A VALUE="$USER_HOME/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/Base/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Processors/Atmel/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/DecompilerDependent/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/PDB/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Features/MicrosoftCodeAnalyzer/ghidra_scripts" />
                <A VALUE="$GHIDRA_HOME/Processors/PIC/ghidra_scripts" />
            </ARRAY>
            <ARRAY NAME="BundleHost_SYSTEM" TYPE="boolean">
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="false" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
                <A VALUE="true" />
            </ARRAY>
            <STATE NAME="FILTER_TEXT" TYPE="string" VALUE="" />
            <ARRAY NAME="RECENT_SCRIPTS" TYPE="string" />
            <ARRAY NAME="Scripts_Actions_Key" TYPE="string" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.bookmark.BookmarkPlugin">
            <ARRAY NAME="BOOKMARK_TYPES" TYPE="string" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.byteviewer.ByteViewerPlugin">
            <STATE NAME="Bytes Per Line" TYPE="int" VALUE="16" />
            <STATE NAME="Charset Name" TYPE="string" VALUE="US-ASCII" />
            <STATE NAME="Compact Chars" TYPE="boolean" VALUE="true" />
            <STATE NAME="Hex View Groupsize" TYPE="int" VALUE="1" />
            <STATE NAME="Offset" TYPE="int" VALUE="0" />
            <STATE NAME="Use Char Alignment" TYPE="boolean" VALUE="true" />
            <ARRAY NAME="View Names" TYPE="string">
                <A VALUE="Hex" />
            </ARRAY>
            <SAVE_STATE NAME="View_Widths" KEY="View_Widths" TYPE="SaveState">
                <STATE NAME="Addresses" TYPE="int" VALUE="100" />
                <STATE NAME="Hex" TYPE="int" VALUE="343" />
            </SAVE_STATE>
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.features.codecompare.plugin.FunctionComparisonPlugin">
            <SAVE_STATE NAME="UNNAMED" KEY="CodeComparisonStates" TYPE="SaveState" />
            <SAVE_STATE NAME="UNNAMED" KEY="FunctionComparison" TYPE="SaveState" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin">
            <SAVE_STATE NAME="COMPLEX_LAYOUT_NAME" KEY="COMPLEX_LAYOUT_NAME" TYPE="SaveState">
                <STATE NAME="LAYOUT_CLASS_NAME" TYPE="string" VALUE="ghidra.app.plugin.core.functiongraph.graph.layout.DecompilerNestedLayoutProvider" />
                <STATE NAME="LAYOUT_NAME" TYPE="string" VALUE="Nested Code Layout" />
            </SAVE_STATE>
            <STATE NAME="DISPLAY_POPUPS" TYPE="boolean" VALUE="true" />
            <STATE NAME="DISPLAY_SATELLITE" TYPE="boolean" VALUE="true" />
            <STATE NAME="DOCK_SATELLITE" TYPE="boolean" VALUE="true" />
            <STATE NAME="DOCK_SATELLITE_POSITION" TYPE="string" VALUE="LOWER_RIGHT" />
            <ENUM NAME="EDGE_HOVER_HIGHLIGHT" TYPE="enum" CLASS="ghidra.app.plugin.core.functiongraph.EdgeDisplayType" VALUE="ScopedFlowsFromVertex" />
            <ENUM NAME="EDGE_SELECTION_HIGHLIGHT" TYPE="enum" CLASS="ghidra.app.plugin.core.functiongraph.EdgeDisplayType" VALUE="AllCycles" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.graph.GraphDisplayBrokerPlugin">
            <STATE NAME="ACTIVE_GRAPH_PROVIDER" TYPE="string" VALUE="Default Graph Display" />
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin">
            <XML NAME="Address Break">
                <FORMAT>
                    <ROW>
                        <FIELD NAME="Separator" WIDTH="80" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="150" ENABLED="true" />
                        <FIELD NAME="Collapsed Code" WIDTH="200" ENABLED="true" />
                    </ROW>
                </FORMAT>
            </XML>
            <XML NAME="Array">
                <FORMAT>
                    <ROW>
                        <FIELD NAME="+" WIDTH="20" ENABLED="true" />
                        <FIELD NAME="Address" WIDTH="100" ENABLED="true" />
                        <FIELD NAME="Field Name" WIDTH="100" ENABLED="true" />
                        <FIELD NAME="Array Values" WIDTH="600" ENABLED="true" />
                    </ROW>
                </FORMAT>
            </XML>
            <STATE NAME="DividerLocation" TYPE="int" VALUE="70" />
            <XML NAME="Function">
                <FORMAT>
                    <ROW>
                        <FIELD NAME="+" WIDTH="20" ENABLED="true" />
                        <FIELD WIDTH="200" ENABLED="true" />
                        <FIELD NAME="Function Signature" WIDTH="410" ENABLED="true" />
                        <FIELD NAME="Function Repeatable Comment" WIDTH="300" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="220" ENABLED="true" />
                        <FIELD NAME="Thunked-Function" WIDTH="300" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="220" ENABLED="true" />
                        <FIELD NAME="Function Call-Fixup" WIDTH="300" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="220" ENABLED="true" />
                        <FIELD NAME="Function Tags" WIDTH="300" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="220" ENABLED="true" />
                        <FIELD NAME="Register" WIDTH="300" ENABLED="true" />
                    </ROW>
                </FORMAT>
            </XML>
            <STATE NAME="Hover Mode" TYPE="boolean" VALUE="true" />
            <XML NAME="Instruction/Data">
                <FORMAT>
                    <ROW>
                        <FIELD WIDTH="90" ENABLED="true" />
                        <FIELD NAME="Register Transition" WIDTH="300" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="200" ENABLED="true" />
                        <FIELD NAME="Pre-Comment" WIDTH="440" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="188" ENABLED="true" />
                        <FIELD NAME="Label" WIDTH="350" ENABLED="true" />
                        <FIELD NAME="XRef Header" WIDTH="90" ENABLED="true" />
                        <FIELD NAME="XRef" WIDTH="240" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="200" ENABLED="true" />
                        <FIELD NAME="Source Map" WIDTH="440" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD NAME="+" WIDTH="20" ENABLED="true" />
                        <FIELD NAME="Address" WIDTH="100" ENABLED="true" />
                        <FIELD NAME="Bytes" WIDTH="80" ENABLED="true" />
                        <FIELD WIDTH="10" ENABLED="true" />
                        <FIELD NAME="Parallel ||" WIDTH="20" ENABLED="true" />
                        <FIELD NAME="Mnemonic" WIDTH="70" ENABLED="true" />
                        <FIELD WIDTH="10" ENABLED="true" />
                        <FIELD NAME="Operands" WIDTH="340" ENABLED="true" />
                        <FIELD NAME="EOL Comment" WIDTH="240" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="380" ENABLED="true" />
                        <FIELD NAME="PCode" WIDTH="400" ENABLED="false" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="200" ENABLED="true" />
                        <FIELD NAME="Post-Comment" WIDTH="440" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD NAME="Space" WIDTH="640" ENABLED="true" />
                    </ROW>
                </FORMAT>
            </XML>
            <XML NAME="Open Data">
                <FORMAT>
                    <ROW>
                        <FIELD NAME="+" WIDTH="20" ENABLED="true" />
                        <FIELD NAME="Address" WIDTH="100" ENABLED="true" />
                        <FIELD NAME="Bytes" WIDTH="110" ENABLED="true" />
                        <FIELD NAME="Mnemonic" WIDTH="70" ENABLED="true" />
                        <FIELD NAME="Operands" WIDTH="170" ENABLED="true" />
                        <FIELD NAME="Field Name" WIDTH="100" ENABLED="true" />
                        <FIELD NAME="EOL Comment" WIDTH="140" ENABLED="true" />
                        <FIELD NAME="XRef Header" WIDTH="90" ENABLED="true" />
                        <FIELD NAME="XRef" WIDTH="240" ENABLED="true" />
                    </ROW>
                </FORMAT>
            </XML>
            <XML NAME="Plate">
                <FORMAT>
                    <ROW>
                        <FIELD WIDTH="200" ENABLED="true" />
                        <FIELD NAME="Memory Block Start" WIDTH="440" ENABLED="true" />
                    </ROW>
                    <ROW>
                        <FIELD WIDTH="200" ENABLED="true" />
                        <FIELD NAME="Plate Comment" WIDTH="440" ENABLED="true" />
                    </ROW>
                </FORMAT>
            </XML>
            <STATE NAME="SHOW_FUNCITON_VARS" TYPE="boolean" VALUE="true" />
            <XML NAME="Variable">
                <FORMAT>
                    <ROW>
                        <FIELD NAME="+" WIDTH="20" ENABLED="true" />
                        <FIELD WIDTH="70" ENABLED="true" />
                        <FIELD NAME="Variable Type" WIDTH="110" ENABLED="true" />
                        <FIELD NAME="Variable Location" WIDTH="120" ENABLED="true" />
                        <FIELD NAME="Variable Name" WIDTH="280" ENABLED="true" />
                        <FIELD NAME="Variable XRef Header" WIDTH="90" ENABLED="true" />
                        <FIELD NAME="Variable XRef" WIDTH="130" ENABLED="true" />
                        <FIELD NAME="Variable Comment" WIDTH="110" ENABLED="true" />
                    </ROW>
                </FORMAT>
            </XML>
        </PLUGIN_STATE>
        <ROOT_NODE X_POS="80" Y_POS="40" WIDTH="1680" HEIGHT="1000" EX_STATE="0" FOCUSED_OWNER="CodeBrowserPlugin" FOCUSED_NAME="Listing" FOCUSED_TITLE="Listing: ">
            <SPLIT_NODE WIDTH="1664" HEIGHT="890" DIVIDER_LOCATION="165" ORIENTATION="VERTICAL">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="angr Debugger" OWNER="AngrDebuggerPlugin" TITLE="angr Debugger" ACTIVE="true" GROUP="angr.control" INSTANCE_ID="3763713238851908281" />
                </COMPONENT_NODE>
                <SPLIT_NODE WIDTH="1664" HEIGHT="765" DIVIDER_LOCATION="660" ORIENTATION="VERTICAL">
                    <SPLIT_NODE WIDTH="1664" HEIGHT="505" DIVIDER_LOCATION="160" ORIENTATION="HORIZONTAL">
                        <COMPONENT_NODE TOP_INFO="0">
                            <COMPONENT_INFO NAME="Symbol Tree" OWNER="SymbolTreePlugin" TITLE="Symbol Tree" ACTIVE="true" GROUP="Default" INSTANCE_ID="3763713238851908277" />
                            <COMPONENT_INFO NAME="Program Tree" OWNER="ProgramTreePlugin" TITLE="Program Trees" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515940" />
                            <COMPONENT_INFO NAME="DataTypes Provider" OWNER="DataTypeManagerPlugin" TITLE="Data Type Manager" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713241498514104" />
                        </COMPONENT_NODE>
                        <SPLIT_NODE WIDTH="1397" HEIGHT="505" DIVIDER_LOCATION="740" ORIENTATION="HORIZONTAL">
                            <SPLIT_NODE WIDTH="1031" HEIGHT="505" DIVIDER_LOCATION="560" ORIENTATION="HORIZONTAL">
                                <COMPONENT_NODE TOP_INFO="0">
                                    <COMPONENT_INFO NAME="Listing" OWNER="CodeBrowserPlugin" TITLE="Listing: " ACTIVE="true" GROUP="Core" INSTANCE_ID="3763713240613515949" />
                                </COMPONENT_NODE>
                                <COMPONENT_NODE TOP_INFO="0">
                                    <COMPONENT_INFO NAME="Decompiler" OWNER="DecompilePlugin" TITLE="Decompile" ACTIVE="true" GROUP="Default" INSTANCE_ID="3763713240613515941" />
                                </COMPONENT_NODE>
                            </SPLIT_NODE>
                            <SPLIT_NODE WIDTH="366" HEIGHT="505" DIVIDER_LOCATION="520" ORIENTATION="VERTICAL">
                                <COMPONENT_NODE TOP_INFO="0">
                                    <COMPONENT_INFO NAME="Registers" OWNER="AngrDebuggerPlugin" TITLE="Registers" ACTIVE="true" GROUP="angr.state" INSTANCE_ID="3763713238851908282" />
                                </COMPONENT_NODE>
                                <COMPONENT_NODE TOP_INFO="0">
                                    <COMPONENT_INFO NAME="Stack" OWNER="AngrDebuggerPlugin" TITLE="Stack" ACTIVE="true" GROUP="angr.state" INSTANCE_ID="3763713238851908283" />
                                </COMPONENT_NODE>
                            </SPLIT_NODE>
                        </SPLIT_NODE>
                    </SPLIT_NODE>
                    <COMPONENT_NODE TOP_INFO="0">
                        <COMPONENT_INFO NAME="Calls" OWNER="AngrDebuggerPlugin" TITLE="Calls" ACTIVE="true" GROUP="angr.trace" INSTANCE_ID="3763713238851908284" />
                        <COMPONENT_INFO NAME="Memory" OWNER="AngrDebuggerPlugin" TITLE="Memory" ACTIVE="true" GROUP="angr.trace" INSTANCE_ID="3763713238851908285" />
                        <COMPONENT_INFO NAME="Output" OWNER="AngrDebuggerPlugin" TITLE="Output" ACTIVE="true" GROUP="angr.trace" INSTANCE_ID="3763713238851908286" />
                        <COMPONENT_INFO NAME="Paths" OWNER="AngrDebuggerPlugin" TITLE="Paths" ACTIVE="true" GROUP="angr.trace" INSTANCE_ID="3763713238851908287" />
                        <COMPONENT_INFO NAME="Symbols" OWNER="AngrDebuggerPlugin" TITLE="Symbols" ACTIVE="true" GROUP="angr.trace" INSTANCE_ID="3763713240613515936" />
                        <COMPONENT_INFO NAME="Ledger" OWNER="AngrDebuggerPlugin" TITLE="Ledger" ACTIVE="true" GROUP="angr.trace" INSTANCE_ID="3763713240613515937" />
                        <COMPONENT_INFO NAME="Imports &amp; Hooks" OWNER="AngrDebuggerPlugin" TITLE="Imports &amp; Hooks" ACTIVE="true" GROUP="angr.trace" INSTANCE_ID="3763713240613515938" />
                        <COMPONENT_INFO NAME="Function Call Trees" OWNER="CallTreePlugin" TITLE="Function Call Trees" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713238851908278" />
                        <COMPONENT_INFO NAME="Bookmarks" OWNER="BookmarkPlugin" TITLE="Bookmarks" ACTIVE="false" GROUP="Core.Bookmarks" INSTANCE_ID="3763713240613515939" />
                        <COMPONENT_INFO NAME="Console" OWNER="ConsolePlugin" TITLE="Console" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515942" />
                        <COMPONENT_INFO NAME="Virtual Disassembler - Current Instruction" OWNER="DisassembledViewPlugin" TITLE="Disassembled View" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515946" />
                        <COMPONENT_INFO NAME="Memory Map" OWNER="MemoryMapPlugin" TITLE="Memory Map" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713238851908260" />
                        <COMPONENT_INFO NAME="Bundle Manager" OWNER="GhidraScriptMgrPlugin" TITLE="Bundle Manager" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713238851908280" />
                        <COMPONENT_INFO NAME="Script Manager" OWNER="GhidraScriptMgrPlugin" TITLE="Script Manager" ACTIVE="false" GROUP="Script Group" INSTANCE_ID="3763713238851908279" />
                        <COMPONENT_INFO NAME="Bytes" OWNER="ByteViewerPlugin" TITLE="Bytes: No Program" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515943" />
                        <COMPONENT_INFO NAME="Equates Table" OWNER="EquateTablePlugin" TITLE="Equates Table" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515947" />
                        <COMPONENT_INFO NAME="Checksum Generator" OWNER="ComputeChecksumsPlugin" TITLE="Checksum Generator" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515948" />
                        <COMPONENT_INFO NAME="External Programs" OWNER="ReferencesPlugin" TITLE="External Programs" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515951" />
                        <COMPONENT_INFO NAME="Source Files and Transforms" OWNER="SourceFilesTablePlugin" TITLE="Source Files and Transforms" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515952" />
                        <COMPONENT_INFO NAME="Register Manager" OWNER="RegisterPlugin" TITLE="Register Manager" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515953" />
                        <COMPONENT_INFO NAME="Functions Window" OWNER="FunctionWindowPlugin" TITLE="Functions" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713240613515954" />
                        <COMPONENT_INFO NAME="Data Type Preview" OWNER="DataTypePreviewPlugin" TITLE="Data Type Preview" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713241362199212" />
                        <COMPONENT_INFO NAME="Function Call Graph" OWNER="FunctionCallGraphPlugin" TITLE="Function Call Graph" ACTIVE="false" GROUP="Function Call Graph" INSTANCE_ID="3763713241362199213" />
                        <COMPONENT_INFO NAME="Data Types Table" OWNER="DataTypeManagerPlugin" TITLE="Data Types Table" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713241498514105" />
                        <COMPONENT_INFO NAME="Function Tags" OWNER="FunctionTagPlugin" TITLE="Function Tags" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713241498514106" />
                        <COMPONENT_INFO NAME="PyGhidra" OWNER="PyGhidra" TITLE="PyGhidra" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713241599177381" />
                        <COMPONENT_INFO NAME="Comment Window" OWNER="CommentWindowPlugin" TITLE="Comments" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713241599177382" />
                        <COMPONENT_INFO NAME="Data Window" OWNER="DataWindowPlugin" TITLE="Defined Data" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713241599177383" />
                        <COMPONENT_INFO NAME="Symbol Table" OWNER="SymbolTablePlugin" TITLE="Symbol Table" ACTIVE="false" GROUP="symbolTable" INSTANCE_ID="3763713241599177384" />
                        <COMPONENT_INFO NAME="Symbol References" OWNER="SymbolTablePlugin" TITLE="Symbol References" ACTIVE="false" GROUP="symbolTable" INSTANCE_ID="3763713241599177385" />
                        <COMPONENT_INFO NAME="Defined Strings" OWNER="DefinedStringsPlugin" TITLE="Defined Strings" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713241599177386" />
                        <COMPONENT_INFO NAME="Relocation Table" OWNER="RelocationTablePlugin" TITLE="Relocation Table" ACTIVE="false" GROUP="Default" INSTANCE_ID="3763713241599177387" />
                        <COMPONENT_INFO NAME="Function Graph" OWNER="FunctionGraphPlugin" TITLE="Function Graph" ACTIVE="false" GROUP="Function Graph" INSTANCE_ID="3763713241599177389" />
                    </COMPONENT_NODE>
                </SPLIT_NODE>
            </SPLIT_NODE>
        </ROOT_NODE>
        <PREFERENCES>
            <PREFERENCE_STATE NAME="GRAPH_DISPLAY_SERVICE" />
        </PREFERENCES>
        <EXTENSIONS>
            <EXTENSION NAME="DecompFuncUtils">
                <PLUGIN CLASS="decompfuncutils.mcp.McpSessionManagerPlugin" />
                <PLUGIN CLASS="decompfuncutils.SparseTaintMatrixPlugin" />
                <PLUGIN CLASS="decompfuncutils.mcp.McpServerPlugin" />
                <PLUGIN CLASS="decompfuncutils.angr.ui.AngrDebuggerToolChestPlugin" />
                <PLUGIN CLASS="decompfuncutils.angr.ui.AngrDebuggerPlugin" />
                <PLUGIN CLASS="decompfuncutils.FlowLauncherPlugin" />
                <PLUGIN CLASS="decompfuncutils.refine.ui.RefinedDecompilerPlugin" />
                <PLUGIN CLASS="decompfuncutils.flowrecorder.FlowRecorderPlugin" />
                <PLUGIN CLASS="decompfuncutils.MemoryToStructPlugin" />
                <PLUGIN CLASS="decompfuncutils.DataflowDecompilerHoverPlugin" />
                <PLUGIN CLASS="decompfuncutils.VTableHandlerPlugin" />
                <PLUGIN CLASS="decompfuncutils.StructFieldNavigationPlugin" />
                <PLUGIN CLASS="decompfuncutils.LibAFLFuzzerGeneratorPlugin" />
            </EXTENSION>
        </EXTENSIONS>
    </TOOL>
</TOOL_CONFIG>
